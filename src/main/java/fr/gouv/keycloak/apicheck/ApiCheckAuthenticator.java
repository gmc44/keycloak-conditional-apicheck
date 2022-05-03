package fr.gouv.keycloak.apicheck;

import static fr.gouv.keycloak.apicheck.ApiCheckConstants.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ServicesLogger;

public class ApiCheckAuthenticator implements ConditionalAuthenticator {

    private Api         api = new Api();

    @Override
    public boolean matchCondition(AuthenticationFlowContext context)
    {
        // Get Extension Parameters
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        //API
        String ApiRootUrl = config.getConfig().get(CONF_API_ROOT_URL);
        String ApiTokenid = config.getConfig().get(CONF_API_TOKENID);
        String ApiToken = config.getConfig().get(CONF_API_TOKEN);
        String ApiCheckPath = config.getConfig().get(CONF_API_CHECK_PATH);
        String ApiHeadersParameters = config.getConfig().get(CONF_API_HEADERS_PARAMETERS);
        String ApiUserAttrsParameters = config.getConfig().get(CONF_API_USERATTRS_PARAMETERS);
        //Get User
        UserModel user  = context.getUser();
                
        ServicesLogger.LOGGER.debug("Headers="+ApiHeadersParameters);
        ServicesLogger.LOGGER.debug("UserAttribute="+ApiUserAttrsParameters);

        ObjectMapper mapper = new ObjectMapper();

        List<Map<String, String>> headers;
        try {
            headers = mapper.readValue(ApiHeadersParameters, new TypeReference<List<Map<String,String>>>() {});
        } catch (JsonProcessingException e1) {
            headers = new ArrayList<>();
            e1.printStackTrace();
        }

        List<Map<String, String>> userattrs;
        try {
            userattrs = mapper.readValue(ApiUserAttrsParameters, new TypeReference<List<Map<String,String>>>() {});
        } catch (JsonProcessingException e1) {
            userattrs = new ArrayList<>();
            e1.printStackTrace();
        }
        

        // Api Data Payload
        Map<String,String> values = new HashMap<>();

        // Headers
        headers.forEach(headerMap -> {
                try {
                    String headerValue = context.getHttpRequest().getHttpHeaders().getHeaderString(headerMap.get("key"));
                    values.put(headerMap.get("value"), headerValue);
                    ServicesLogger.LOGGER.debug("Header : "+headerMap.get("key")+" = "+headerValue);
                } catch (NullPointerException npe) {
                    ServicesLogger.LOGGER.warn("Failed to read Header : "+headerMap.get("key"));
                }
        });

        // UserAttributes
        userattrs.forEach(userattrsMap -> {
            try {
                String userattrsValue = user.getFirstAttribute(userattrsMap.get("key"));
                values.put(userattrsMap.get("value"), userattrsValue);
                ServicesLogger.LOGGER.debug("User Attribute : "+userattrsMap.get("key")+" = "+userattrsValue);
            } catch (NullPointerException npe) {
                ServicesLogger.LOGGER.warn("Failed to read User Attribute : "+userattrsMap.get("key"));
            }
        });
        
        Boolean res;
        try {
            String data = mapper.writeValueAsString(values);
            ServicesLogger.LOGGER.debug("values="+data);
            res=api.postcheck(ApiRootUrl, ApiTokenid, ApiToken, ApiCheckPath, new StringEntity(data,ContentType.APPLICATION_JSON));
            ServicesLogger.LOGGER.debug("res="+res);
        } catch (IOException e) {
            ServicesLogger.LOGGER.error("Erreur call API : "+e.getMessage(),e);
            res=false;
        }
        return !res; //conditional : return true when condition's needed
    }

    
    @Override
    public boolean requiresUser()
    {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user)
    {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user)
    {
        // not needed for current version
    }

    @Override
    public void close()
    {
        // not used for current version
    }


    @Override
    public void action(AuthenticationFlowContext context) {
        // TODO Auto-generated method stub
        
    }

}