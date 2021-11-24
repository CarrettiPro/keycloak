/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.services.util;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.UriInfo;

import org.jboss.resteasy.spi.HttpRequest;

import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.exceptions.TokenVerificationException;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.crypto.HashUtils;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseTokenStoreProvider;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.dpop.DPoP;
import org.keycloak.util.JWKSUtils;

/**
 * @author <a href="mailto:dmitryt@backbase.com">Dmitry Telegin</a>
 */
public class DPoPUtil {

    public static final int DEFAULT_PROOF_LIFETIME = 10;
    public static final int DEFAULT_ALLOWED_CLOCK_SKEW = 2;
    public static final String DPOP_TOKEN_TYPE = "DPoP";
    public static final String DPOP_SCHEME = "DPoP";
    public final static String DPOP_SESSION_ATTRIBUTE = "dpop";

    public static enum Mode {
        ENABLED,
        OPTIONAL,
        DISABLED
    }

    private static final String DPOP_HEADER = "DPoP";
    private static final String DPOP_HEADER_TYPE = "dpop+jwt";
    private static final String DPOP_ATH_ALG = "RS256";

    public static final Set<String> DPOP_SUPPORTED_ALGS = Stream.of(
        Algorithm.ES256,
        Algorithm.ES384,
        Algorithm.ES512,
        Algorithm.PS256,
        Algorithm.PS384,
        Algorithm.PS512,
        Algorithm.RS256,
        Algorithm.RS384,
        Algorithm.RS512
    ).collect(Collectors.toSet());

    public static DPoP validateDPoP(KeycloakSession session, ClientModel client, HttpHeaders headers, HttpRequest request, UriInfo uri) throws VerificationException {
        return validateDPoP(session, client, headers, request, uri, null);
    }

    public static DPoP validateDPoP(KeycloakSession session, ClientModel client, HttpHeaders headers, HttpRequest request, UriInfo uri, String tokenString) throws VerificationException {
        String token = headers.getHeaderString(DPOP_HEADER);

        if (token == null || token.trim().equals("")) {
            throw new VerificationException("DPoP proof is missing");
        }

        TokenVerifier<DPoP> verifier = TokenVerifier.create(token, DPoP.class);
        JWSHeader header;

        try {
            header = verifier.getHeader();
        } catch (VerificationException ex) {
            throw new VerificationException("DPoP header verification failure");
        }

        if (!DPOP_HEADER_TYPE.equals(header.getType())) {
            throw new VerificationException("Invalid or missing type in DPoP header: " + header.getType());
        }

        String algorithm = header.getAlgorithm().name();

        if (!DPOP_SUPPORTED_ALGS.contains(algorithm)) {
            throw new VerificationException("Unsupported DPoP algorithm: " + header.getAlgorithm());
        }

        JWK key = header.getKey();

        if (key == null) {
            throw new VerificationException("No JWK in DPoP header");
        } else {
            KeyWrapper wrapper = JWKSUtils.getKeyWrapper(key);
            if (wrapper.getPublicKey() == null) {
                throw new VerificationException("No public key in DPoP header");
            }
            if (wrapper.getPrivateKey() != null) {
                throw new VerificationException("Private key is present in DPoP header");
            }
        }

        key.setAlgorithm(header.getAlgorithm().name());

        SignatureVerifierContext signatureVerifier = session.getProvider(SignatureProvider.class, algorithm).verifier(key);
        verifier.verifierContext(signatureVerifier);
        verifier.withChecks(
                DPoPClaimsCheck.INSTANCE,
                new DPoPHTTPCheck(request, uri),
                new DPoPIsActiveCheck(session, client),
                new DPoPReplayCheck(session, client));

        if (tokenString != null) {
            verifier.withChecks(new DPoPAccessTokenHashCheck(tokenString));
        }

        try {
            DPoP dPoP = verifier.verify().getToken();
            dPoP.setThumbprint(JWKSUtils.computeThumbprint(key));
            return dPoP;
        } catch (DPoPVerificationException ex) {
            throw ex;
        } catch (VerificationException ex) {
            throw new VerificationException("DPoP verification failure", ex);
        }

    }

    public static void validateBinding(AccessToken token, DPoP dPoP) throws VerificationException {
        try {
            TokenVerifier.createWithoutSignature(token)
                    .withChecks(new DPoPUtil.DPoPBindingCheck(dPoP))
                    .verify();
        } catch (TokenVerificationException ex) {
            throw ex;
        } catch (VerificationException ex) {
            throw new VerificationException("Token verification failure", ex);
        }
    }

    public static void bindToken(AccessToken token, DPoP dPoP) {
        AccessToken.Confirmation confirmation = token.getConfirmation();

        if (confirmation == null) {
            confirmation = new AccessToken.Confirmation();
            token.setConfirmation(confirmation);
        }

        confirmation.setKeyThumbprint(dPoP.getThumbprint());
    }

    private static class DPoPClaimsCheck implements TokenVerifier.Predicate<DPoP> {

        static final TokenVerifier.Predicate<DPoP> INSTANCE = new DPoPClaimsCheck();

        @Override
        public boolean test(DPoP t) throws DPoPVerificationException {
            Long iat = t.getIat();
            String jti = t.getId(), htu = t.getHttpUri(), htm = t.getHttpMethod();

            if (iat != null &&
                jti != null && !jti.trim().equals("") &&
                htm != null && !htm.trim().equals("") &&
                htu != null && !htu.trim().equals("")) {
                return true;
            } else {
                throw new DPoPVerificationException(t, "DPoP mandatory claims are missing");
            }
        }

    }

    private static class DPoPHTTPCheck implements TokenVerifier.Predicate<DPoP> {

        private final HttpRequest request;
        private final UriInfo uri;

        DPoPHTTPCheck(HttpRequest request, UriInfo uri) {
            this.request = request;
            this.uri = uri;
        }

        @Override
        public boolean test(DPoP t) throws DPoPVerificationException {
            try {
                if (new URI(t.getHttpUri()).equals(uri.getAbsolutePath()) &&
                    request.getHttpMethod().equals(t.getHttpMethod())) {
                    return true;
                } else {
                    throw new DPoPVerificationException(t, "DPoP HTTP method/URL mismatch");
                }
            } catch (URISyntaxException ex) {
                throw new DPoPVerificationException(t, "Malformed HTTP URL in DPoP proof");
            }
        }

    }

    private static class DPoPReplayCheck implements TokenVerifier.Predicate<DPoP> {

        private final KeycloakSession session;
        private final int lifetime;

        public DPoPReplayCheck(KeycloakSession session, ClientModel client) {
            this.session = session;
            OIDCAdvancedConfigWrapper config = OIDCAdvancedConfigWrapper.fromClientModel(client);
            this.lifetime = config.getDPoPProofLifetime();
        }

        @Override
        public boolean test(DPoP t) throws DPoPVerificationException {
            SingleUseTokenStoreProvider singleUseCache = session.getProvider(SingleUseTokenStoreProvider.class);
            byte[] hash = HashUtils.hash("SHA1", (t.getId() + "\n" + t.getHttpUri()).getBytes());
            String hashString = HashUtils.encodeHashToHex(hash);
            if (!singleUseCache.putIfAbsent(hashString, (int)(t.getIat() + lifetime - Time.currentTime()))) {
                throw new DPoPVerificationException(t, "DPoP proof has already been used");
            }
            return true;
        }

    }

    private static class DPoPIsActiveCheck implements TokenVerifier.Predicate<DPoP> {

        private final int clockSkew;
        private final int lifetime;

        public DPoPIsActiveCheck(KeycloakSession session, ClientModel client) {
            OIDCAdvancedConfigWrapper config = OIDCAdvancedConfigWrapper.fromClientModel(client);
            this.clockSkew = config.getDPoPAllowedClockSkew();
            this.lifetime = config.getDPoPProofLifetime();
        }

        @Override
        public boolean test(DPoP t) throws DPoPVerificationException {
            long time = Time.currentTime();
            Long iat = t.getIat();

            if (!(iat <= time + clockSkew && iat > time - lifetime)) {
                throw new DPoPVerificationException(t, "DPoP proof is not active");
            }
            return true;
        }
    }

    private static class DPoPAccessTokenHashCheck implements TokenVerifier.Predicate<DPoP> {

        private String hash;

        public DPoPAccessTokenHashCheck(String tokenString) {
            hash = HashUtils.oidcHash(DPOP_ATH_ALG, tokenString, true);
        }

        @Override
        public boolean test(DPoP t) throws DPoPVerificationException {
            if (t.getAccessTokenHash() == null) {
                throw new DPoPVerificationException(t, "No access token hash in DPoP proof");
            }
            if (!t.getAccessTokenHash().equals(hash)) {
                throw new DPoPVerificationException(t, "DPoP proof access token hash mismatch");
            }
            return true;
        }

    }

    public static class DPoPBindingCheck implements TokenVerifier.Predicate<AccessToken> {

        private final DPoP proof;

        public DPoPBindingCheck(DPoP proof) {
            this.proof = proof;
        }

        @Override
        public boolean test(AccessToken t) throws VerificationException {
            String thumbprint = proof.getThumbprint();

            AccessToken.Confirmation confirmation = t.getConfirmation();
            if (confirmation == null) {
                throw new TokenVerificationException(t, "No DPoP confirmation in access token");
            }
            String keyThumbprint = confirmation.getKeyThumbprint();
            if (keyThumbprint == null) {
                throw new TokenVerificationException(t, "No DPoP key thumbprint in access token");
            }
            if (!keyThumbprint.equals(thumbprint)) {
                throw new TokenVerificationException(t, "DPoP confirmation doesn't match DPoP proof");
            }
            return true;
        }

    }

    public static class DPoPVerificationException extends TokenVerificationException {

        public DPoPVerificationException(DPoP token, String message) {
            super(token, message);
        }

    }

}
