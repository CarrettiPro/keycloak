/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.util;

import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jws.crypto.HashUtils;

import java.io.IOException;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import org.keycloak.crypto.KeyType;
import org.keycloak.jose.jwk.ECPublicJWK;
import org.keycloak.jose.jwk.RSAPublicJWK;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class JWKSUtils {

    private static final String JWK_THUMBPRINT_DEFAULT_HASH_ALGORITHM = "SHA-256";

    private static final Map<String, String[]> JWK_THUMBPRINT_REQUIRED_MEMBERS = new HashMap<>();
    
    static {
        JWK_THUMBPRINT_REQUIRED_MEMBERS.put(KeyType.RSA, new String[] { RSAPublicJWK.MODULUS, RSAPublicJWK.PUBLIC_EXPONENT });
        JWK_THUMBPRINT_REQUIRED_MEMBERS.put(KeyType.EC, new String[] { ECPublicJWK.CRV, ECPublicJWK.X, ECPublicJWK.Y });
    }

    public static Map<String, PublicKey> getKeysForUse(JSONWebKeySet keySet, JWK.Use requestedUse) {
        Map<String, PublicKey> result = new HashMap<>();

        for (JWK jwk : keySet.getKeys()) {
            JWKParser parser = JWKParser.create(jwk);
            if (jwk.getPublicKeyUse().equals(requestedUse.asString()) && parser.isKeyTypeSupported(jwk.getKeyType())) {
                result.put(jwk.getKeyId(), parser.toPublicKey());
            }
        }

        return result;
    }

    public static Map<String, KeyWrapper> getKeyWrappersForUse(JSONWebKeySet keySet, JWK.Use requestedUse) {
        Map<String, KeyWrapper> result = new HashMap<>();
        for (JWK jwk : keySet.getKeys()) {
            JWKParser parser = JWKParser.create(jwk);
            if (jwk.getPublicKeyUse().equals(requestedUse.asString()) && parser.isKeyTypeSupported(jwk.getKeyType())) {
                KeyWrapper keyWrapper = wrap(jwk, parser);
                result.put(keyWrapper.getKid(), keyWrapper);
            }
        }
        return result;
    }

    private static KeyUse getKeyUse(String keyUse) {
        switch (keyUse) {
            case "sig" : 
                return KeyUse.SIG;
            case "enc" : 
                return KeyUse.ENC;
            default :
                return null;
        }
    }

    public static JWK getKeyForUse(JSONWebKeySet keySet, JWK.Use requestedUse) {
        for (JWK jwk : keySet.getKeys()) {
            JWKParser parser = JWKParser.create(jwk);
            if (parser.getJwk().getPublicKeyUse().equals(requestedUse.asString()) && parser.isKeyTypeSupported(jwk.getKeyType())) {
                return jwk;
            }
        }

        return null;
    }
    
    public static KeyWrapper getKeyWrapper(JWK jwk) {
        JWKParser parser = JWKParser.create(jwk);
        if (parser.isKeyTypeSupported(jwk.getKeyType())) {
            return wrap(jwk, parser);
        } else {
            return null;
        }
    }

    private static KeyWrapper wrap(JWK jwk, JWKParser parser) {
        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setKid(jwk.getKeyId());
        if (jwk.getAlgorithm() != null) {
            keyWrapper.setAlgorithm(jwk.getAlgorithm());
        }
        else if (jwk.getKeyType().equalsIgnoreCase("RSA")){
            //backwards compatibility: RSA keys without "alg" field set are considered RS256
            keyWrapper.setAlgorithm("RS256");
        }
        keyWrapper.setType(jwk.getKeyType());
        if (jwk.getPublicKeyUse() != null)
            keyWrapper.setUse(getKeyUse(jwk.getPublicKeyUse()));
        keyWrapper.setPublicKey(parser.toPublicKey());
        return keyWrapper;
    }

    public static String computeThumbprint(JWK key)  {
        return computeThumbprint(key, JWK_THUMBPRINT_DEFAULT_HASH_ALGORITHM);
    }
    
    public static String computeThumbprint(JWK key, String hashAlg)  {        
        Map<String, String> members = new TreeMap<>();
        members.put(JWK.KEY_TYPE, key.getKeyType());
        
        for (String member : JWK_THUMBPRINT_REQUIRED_MEMBERS.get(key.getKeyType())) {
            members.put(member, (String) key.getOtherClaims().get(member));
        }
        
        try {
            byte[] bytes = JsonSerialization.writeValueAsBytes(members);
            byte[] hash = HashUtils.hash(hashAlg, bytes);
            return Base64Url.encode(hash);
        } catch (IOException ex) {
            return null;
        }
    }
    
}
