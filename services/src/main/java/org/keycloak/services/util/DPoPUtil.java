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
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.dpop.DPoP;
import org.keycloak.util.JWKSUtils;

public class DPoPUtil {

    private static final String DPOP_HEADER = "DPoP";
    private static final String DPOP_HEADER_TYPE = "dpop+jwt";
    private static final Set<String> DPOP_SUPPORTED_ALGS = Stream.of(
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

    public static DPoP validateDPoP(KeycloakSession session, HttpHeaders headers, HttpRequest request, UriInfo uri) throws VerificationException {
        String token = headers.getHeaderString(DPOP_HEADER);
        TokenVerifier<DPoP> verifier = TokenVerifier.create(token, DPoP.class);

        JWSHeader header = verifier.getHeader();

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
        DPoP dpop = verifier.withChecks(new DPoPClaimsCheck(), new DPoPHTTPCheck(request, uri)).verify().getToken();
        dpop.setThumbprint(JWKSUtils.computeThumbprint(key));
        return dpop;
    }

    private static class DPoPClaimsCheck implements TokenVerifier.Predicate<DPoP> {

        @Override
        public boolean test(DPoP t) throws VerificationException {
            Long iat = t.getIat();
            String jti = t.getId(), htu = t.getHttpUri(), htm = t.getHttpMethod();

            return iat != null &&
                jti != null && !jti.trim().equals("") &&
                htm != null && !htm.trim().equals("") &&
                htu != null && !htu.trim().equals("");
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
        public boolean test(DPoP t) throws VerificationException {
            try {
                return new URI(t.getHttpUri()).equals(uri.getAbsolutePath()) &&
                    request.getHttpMethod().equals(t.getHttpMethod());
            } catch (URISyntaxException ex) {
                return false;
            }
        }
        
    }

}
