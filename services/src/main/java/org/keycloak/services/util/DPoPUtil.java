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
import org.keycloak.exceptions.TokenNotActiveException;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.TokenRevocationStoreProvider;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.representations.dpop.DPoP;
import org.keycloak.util.JWKSUtils;

public class DPoPUtil {

    public static final int DEFAULT_PROOF_LIFETIME = 10;
    public static final int DEFAULT_ALLOWED_CLOCK_SKEW = 2;
    public static final String DPOP_TOKEN_TYPE = "DPoP";

    public static enum Mode {
        ENABLED,
        OPTIONAL,
        DISABLED
    }

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
        DPoP dpop = verifier.withChecks(
                DPoPClaimsCheck.INSTANCE,
                new DPoPHTTPCheck(request, uri),
                new DPoPIsActiveCheck(session),
                new DPoPReplayCheck(session)).verify().getToken();
        dpop.setThumbprint(JWKSUtils.computeThumbprint(key));
        return dpop;
    }

    private static class DPoPClaimsCheck implements TokenVerifier.Predicate<DPoP> {

        static final TokenVerifier.Predicate<DPoP> INSTANCE = new DPoPClaimsCheck();

        @Override
        public boolean test(DPoP t) throws VerificationException {
            Long iat = t.getIat();
            String jti = t.getId(), htu = t.getHttpUri(), htm = t.getHttpMethod();

            if (iat != null &&
                jti != null && !jti.trim().equals("") &&
                htm != null && !htm.trim().equals("") &&
                htu != null && !htu.trim().equals("")) {
                return true;
            } else {
                throw new VerificationException("DPoP mandatory claims are missing");
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
        public boolean test(DPoP t) throws VerificationException {
            try {
                if (new URI(t.getHttpUri()).equals(uri.getAbsolutePath()) &&
                    request.getHttpMethod().equals(t.getHttpMethod())) {
                    return true;
                } else {
                    throw new VerificationException("DPoP HTTP method/URL mismatch");
                }
            } catch (URISyntaxException ex) {
                throw new VerificationException("Malformed HTTP URL in DPoP proof");
            }
        }

    }

    private static class DPoPReplayCheck implements TokenVerifier.Predicate<DPoP> {

        private final KeycloakSession session;
        private final int lifetime;

        public DPoPReplayCheck(KeycloakSession session) {
            this.session = session;
            ClientModel client = session.getContext().getClient();
            OIDCAdvancedConfigWrapper config = OIDCAdvancedConfigWrapper.fromClientModel(client);
            this.lifetime = config.getDPoPProofLifetime();
        }

        @Override
        public boolean test(DPoP t) throws VerificationException {
            TokenRevocationStoreProvider revocation = session.getProvider(TokenRevocationStoreProvider.class);
            if (revocation.isRevoked(t.getId())) {
                throw new TokenNotActiveException(t, "DPoP proof has been revoked");
            } else {
                revocation.putRevokedToken(t.getId(), t.getIat() + lifetime - Time.currentTime());
                return true;
            }
        }

    }

    private static class DPoPIsActiveCheck implements TokenVerifier.Predicate<DPoP> {

        private final int clockSkew;
        private final int lifetime;

        public DPoPIsActiveCheck(KeycloakSession session) {
            ClientModel client = session.getContext().getClient();
            OIDCAdvancedConfigWrapper config = OIDCAdvancedConfigWrapper.fromClientModel(client);
            this.clockSkew = config.getDPoPAllowedClockSkew();
            this.lifetime = config.getDPoPProofLifetime();
        }

        @Override
        public boolean test(DPoP t) throws VerificationException {
            long time = Time.currentTime();
            Long iat = t.getIat();

            if (!(iat <= time + clockSkew && iat > time - lifetime)) {
                throw new TokenNotActiveException(t, "DPoP proof is not active");
            }
            return true;
        }
    }

}
