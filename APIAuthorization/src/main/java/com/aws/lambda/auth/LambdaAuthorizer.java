package com.aws.lambda.auth;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class LambdaAuthorizer implements RequestHandler<APIGatewayProxyRequestEvent, Response> {
    public Response handleRequest(APIGatewayProxyRequestEvent event, Context context) {
        Map<String, String> headers = event.getHeaders();
        String authorizationToken = headers.get("Authorization");
        String auth = "Deny";
        String sub = JWTUtil.getSub(authorizationToken);
        if (sub != null) {
            auth = "Allow";
        }
        Map<String, String> ctx = new HashMap<String, String>();
        ctx.put("sub", sub);
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyContext = event.getRequestContext();
        APIGatewayProxyRequestEvent.RequestIdentity identity = proxyContext.getIdentity();
        
        String arn = String.format("arn:aws:execute-api:%s:%s:%s/%s/%s/%s","us-east-1", proxyContext.getAccountId(),
                proxyContext.getApiId(), proxyContext.getStage(), proxyContext.getHttpMethod(), "*");
        Statement statement = Statement.builder().effect(auth).resource(arn).build();
        PolicyDocument policyDocument = PolicyDocument.builder().statements(Collections.singletonList(statement))
                .build();
        return Response.builder().principalId(identity.getAccountId()).policyDocument(policyDocument)
                .context(ctx).build();
    }
}