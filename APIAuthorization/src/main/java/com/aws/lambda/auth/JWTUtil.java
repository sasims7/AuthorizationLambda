package com.aws.lambda.auth;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
public class JWTUtil {
    static ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
    static {
        try {
            JWKSource keySource = null;
            //Following url needs to be updated with the correct region and user pool id
            keySource = new RemoteJWKSet(
                    new URL("https://cognito-idp."+"us-east-1"+".amazonaws.com/"+"{UserPoolIdHere}"+"/.well-known/jwks.json"));
            JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;
            JWSKeySelector keySelector = new JWSVerificationKeySelector(expectedJWSAlg, keySource);
            jwtProcessor.setJWSKeySelector(keySelector);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
    }
    public static String getSub(String token)  {
        SecurityContext ctx = null; 
        JWTClaimsSet claimsSet = null;
        try {
            claimsSet = jwtProcessor.process(token, ctx);
            return claimsSet.getStringClaim("sub");
        } catch (BadJOSEException e) {
            e.printStackTrace();
        } catch (JOSEException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return null;     
    }
    
	/*
	 * public static void main(String[] args) { SecurityContext ctx = null;
	 * JWTClaimsSet claimsSet = null; String token =
	 * "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ";
	 * try { claimsSet = jwtProcessor.process(token, ctx);
	 * System.out.println(claimsSet.getStringClaim("sub")); } catch
	 * (BadJOSEException e) { e.printStackTrace(); } catch (JOSEException e) {
	 * e.printStackTrace(); } catch (ParseException e) { // TODO Auto-generated
	 * catch block e.printStackTrace(); } }
	 */
}