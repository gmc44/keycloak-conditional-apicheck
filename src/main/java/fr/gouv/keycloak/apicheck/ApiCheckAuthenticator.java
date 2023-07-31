package fr.gouv.keycloak.apicheck;

import static fr.gouv.keycloak.apicheck.ApiCheckConstants.*;

import java.io.IOException;
import java.net.SocketException;
import java.nio.charset.UnsupportedCharsetException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.http.client.ClientProtocolException;
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
    
    // logger using keyloak.services.ServicesLogger
    private static final ServicesLogger logger = ServicesLogger.LOGGER;

    String Module = "ApiCheck : ";
    
    private Api         api = new Api();

    private int getHardTimeout(String confHardTimeout) {
        int hardTimeout;
        int defaultHardTimeout = 2;

        // String is empty
        if (confHardTimeout == null) { return defaultHardTimeout; }

        // Try to parse confString
        try {
            hardTimeout = Integer.parseInt(confHardTimeout);
        } catch (NullPointerException npe) {
            hardTimeout = defaultHardTimeout;
            logger.warn(Module+"failed to read Timeout : "+confHardTimeout);
        }

        if (hardTimeout > 0) {
            return hardTimeout;
        } else {
            return defaultHardTimeout;
        }

    }

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
        String ApiCheckHardTimeout = config.getConfig().get(CONF_API_HARD_TIMEOUT);
        String ApiCheckHardTimeoutDefaultResponse = config.getConfig().get(CONF_API_HARD_TIMEOUT_DEFAULT_RESPONSE);
        String ApiHeadersParameters = config.getConfig().get(CONF_API_HEADERS_PARAMETERS);
        String ApiUserAttrsParameters = config.getConfig().get(CONF_API_USERATTRS_PARAMETERS);
        String ApiAuthNotesParameters = config.getConfig().get(CONF_API_AUTHNOTES_PARAMETERS);
        //Get User
        UserModel user  = context.getUser();
                
        logger.debug(Module+"Headers="+ApiHeadersParameters);
        logger.debug(Module+"UserAttribute="+ApiUserAttrsParameters);
        logger.debug(Module+"AuthNotes="+ApiAuthNotesParameters);

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

        List<Map<String, String>> authnotes;
        try {
            authnotes = mapper.readValue(ApiAuthNotesParameters, new TypeReference<List<Map<String,String>>>() {});
        } catch (JsonProcessingException e1) {
            authnotes = new ArrayList<>();
            e1.printStackTrace();
        }
        

        // Api Data Payload
        Map<String,String> values = new HashMap<>();

        // Headers
        headers.forEach(headerMap -> {
            try {
                String headerValue = context.getHttpRequest().getHttpHeaders().getHeaderString(headerMap.get("key"));
                if (headerValue == null) {
                    headerValue = "";
                }
                values.put(headerMap.get("value"), headerValue);
                logger.debug(Module+"Header : "+headerMap.get("key")+" = "+headerValue);
            } catch (NullPointerException npe) {
                logger.warn(Module+"Failed to read Header : "+headerMap.get("key"));
            }
        });

        // UserAttributes
        userattrs.forEach(userattrsMap -> {
            try {
                // String userattrValue = user.getFirstAttribute(userattrsMap.get("key"));
                String userattrValue = user.getAttributeStream(userattrsMap.get("key")).collect(Collectors.joining("##"));
                if (userattrValue == null) {
                    userattrValue = "";
                }
                values.put(userattrsMap.get("value"), userattrValue);
                logger.debug(Module+"User Attribute : "+userattrsMap.get("key")+" = "+userattrValue);
            } catch (NullPointerException npe) {
                logger.warn(Module+"Failed to read User Attribute : "+userattrsMap.get("key"));
            }
        });

        // AuthNotes
        authnotes.forEach(authnotesMap -> {
            try {
                String authnoteValue = context.getAuthenticationSession().getAuthNote(authnotesMap.get("key"));
                if (authnoteValue == null) {
                    authnoteValue = "";
                }
                values.put(authnotesMap.get("value"), authnoteValue);
                logger.debug(Module+"AuthNote : "+authnotesMap.get("key")+" = "+authnoteValue);
            } catch (NullPointerException npe) {
                logger.warn(Module+"Failed to read Note : "+authnotesMap.get("key"));
            }
        });
            
        
        // Initialize Default Response
        Boolean res = Boolean.valueOf(ApiCheckHardTimeoutDefaultResponse);

        // Get Hard Timeout
        int hardTimeout = getHardTimeout(ApiCheckHardTimeout);
        
        // Map Values
        String data;
        try {
            data = mapper.writeValueAsString(values);
            logger.debug(Module+"values="+data);
        } catch (JsonProcessingException e1) {
            logger.warn(Module+"Unable to map values, return default : "+res);
            return res;
        }

        String logReturnDefault = "RETURN Default ("+res+"): "+ApiRootUrl+ApiCheckPath+" ";
        try {
            res=api.postcheck(ApiRootUrl, ApiTokenid, ApiToken, ApiCheckPath, new StringEntity(data,ContentType.APPLICATION_JSON), hardTimeout);
        } catch (SocketException e) {
            logger.warn(Module+logReturnDefault+"HardTimeout Reached");
        } catch (UnsupportedCharsetException e) {
            logger.warn(Module+logReturnDefault+"Unsupported Charset : "+e.toString());
        } catch (ClientProtocolException e) {
            logger.warn(Module+logReturnDefault+"Client Protocol Error : "+e.toString());
        } catch (IOException e) {
            logger.warn(Module+logReturnDefault+"Call API IOError : "+e.toString());
        } catch (Exception e) {
            logger.warn(Module+logReturnDefault+"Call API Error : "+e.toString());
        };

        return res; //conditional : return true when condition is needed
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