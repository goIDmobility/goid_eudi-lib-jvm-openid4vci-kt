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

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.jwk.AsymmetricJWK
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jose.util.X509CertChainUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.http.CredentialIssuerMetadataJsonParser
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*

private val CONTENT_TYPE_APPLICATION_JWT = ContentType.parse("application/jwt")

internal class DefaultCredentialIssuerMetadataResolver(
    private val httpClient: HttpClient,
) : CredentialIssuerMetadataResolver {

    override suspend fun resolve(
        issuer: CredentialIssuerId,
        policy: IssuerMetadataPolicy,
    ): Result<CredentialIssuerMetadata> = runCatching {
        val wellKnownUrl = issuer.wellKnownUrl("/.well-known/openid-credential-issuer")
        try {
            val json =  httpClient.get(wellKnownUrl).body<String>()
            CredentialIssuerMetadataJsonParser.parseMetaData(json, issuer)
        } catch (t: Throwable) {
            val wellKnownUrl = issuer.wellKnownUrl("/.well-known/openid-credential-issuer", false)
             try {
                 val json =  httpClient.get(wellKnownUrl).body<String>()
                 CredentialIssuerMetadataJsonParser.parseMetaData(json, issuer)
             } catch (t: Throwable) {
                throw t
            }
        }
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

private fun CredentialIssuerId.wellKnownUrl(wellKnownPath: String, trailingSlash: Boolean = true): Url {
    val issuer = Url(this.value.value.toString())
    val pathSegment = buildString {
        append("/${wellKnownPath.removePrefixAndSuffix("/")}")
        val joinedSegments = issuer.segments.joinToString(separator = "/")
        if (joinedSegments.isNotBlank()) {
            append("/")
        }
        append(joinedSegments)
        if (trailingSlash) append("/")
    }

    return URLBuilder(issuer).apply { path(pathSegment) }.build()
}


