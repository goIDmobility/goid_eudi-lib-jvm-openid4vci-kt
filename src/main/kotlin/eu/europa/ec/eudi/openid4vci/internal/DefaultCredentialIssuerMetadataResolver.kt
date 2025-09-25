/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.openid4vci.internal

import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.http.CredentialIssuerMetadataJsonParser
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import java.net.URL

internal class DefaultCredentialIssuerMetadataResolver(
    private val httpClient: HttpClient,
) : CredentialIssuerMetadataResolver {

    override suspend fun resolve(
        issuer: CredentialIssuerId,
        policy: IssuerMetadataPolicy,
    ): Result<CredentialIssuerMetadata> = runCatching {
        val wellKnownUrl = issuer.wellKnown()
        val json = try {
           var value = httpClient.get(wellKnownUrl).body<String>()
            if(isNotJson(value)) {
                val httpUrl = wellKnownUrl(issuer.value.value, "/.well-known/openid-credential-issuer")
                  value = httpClient.get(httpUrl).body<String>()
            }
            value
        } catch (t: Throwable) {
            throw CredentialIssuerMetadataError.UnableToFetchCredentialIssuerMetadata(t)
        }

        if(isNotJson(json)) {
            throw CredentialIssuerMetadataError.UnableToFetchCredentialIssuerMetadata(IllegalArgumentException("Not a valid credential meta data"))
        }


        CredentialIssuerMetadataJsonParser.parseMetaData(json, issuer, policy)
    }
}

fun isNotJson(input: String): Boolean {
    return try {
        kotlinx.serialization.json.Json.parseToJsonElement(input)
        false
    } catch (e: Exception) {
        true
    }
}

private fun  wellKnownUrl(url: URL, wellKnownPath: String): Url {
    val issuer = Url(url.toString())
    val pathSegment = buildString {
        append("/${wellKnownPath.removePrefixAndSuffix("/")}")
        val joinedSegments = issuer.segments.joinToString(separator = "/")
        if (joinedSegments.isNotBlank()) {
            append("/")
        }
        append(joinedSegments)
    }

    return URLBuilder(issuer).apply { path(pathSegment) }.build()
}

private fun CredentialIssuerId.wellKnown() = URLBuilder(Url(value.value.toURI()))
    .appendPathSegments("/.well-known/openid-credential-issuer", encodeSlash = false)
    .build()
    .toURI()
    .toURL()
