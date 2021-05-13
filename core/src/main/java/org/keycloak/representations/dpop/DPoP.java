package org.keycloak.representations.dpop;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.representations.JsonWebToken;

public class DPoP extends JsonWebToken {
    
    private static final String ATH = "ath";
    private static final String HTM = "htm";
    private static final String HTU = "htu";
    
    @JsonProperty(ATH)
    private String accessTokenHash;

    @JsonProperty(HTM)
    private String httpMethod;
    
    @JsonProperty(HTU)
    private String httpUri;
    
    public String getAccessTokenHash() {
        return accessTokenHash;
    }
    public void setAccessTokenHash(String accessTokenHash) {
        this.accessTokenHash = accessTokenHash;
    }
    
    public String getHttpMethod() {
        return httpMethod;
    }

    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }

    public String getHttpUri() {
        return httpUri;
    }

    public void setHttpUri(String httpUri) {
        this.httpUri = httpUri;
    }
    
}
