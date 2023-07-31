package fr.gouv.keycloak.apicheck;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;


public class ApiCheckAuthenticatorFactory
    implements AuthenticatorFactory
{

    public static final String ID = "keycloak-conditional-apicheck";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED,
            AuthenticationExecutionModel.Requirement.CONDITIONAL
    };

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property;
        //API
        property = new ProviderConfigProperty();
        property.setName(ApiCheckConstants.CONF_API_ROOT_URL);
        property.setLabel("Api root URL");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Enter your Api root URL");
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(ApiCheckConstants.CONF_API_TOKENID);
        property.setLabel("[Optional] Api TokenId");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Enter your Api Token Name");
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(ApiCheckConstants.CONF_API_TOKEN);
        property.setLabel("[Optional] Api Token");
        property.setType(ProviderConfigProperty.PASSWORD);
        property.setHelpText("Enter your Api Token Key");
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(ApiCheckConstants.CONF_API_CHECK_PATH);
        property.setLabel("Api check PATH");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Enter your Api Check PATH");
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(ApiCheckConstants.CONF_API_HARD_TIMEOUT);
        property.setLabel("Api check Hard Timeout (s) - default 2s");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("While setting timeouts on establishing the HTTP connection and not receiving data is very useful, sometimes we need to set a hard timeout for the entire request");
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(ApiCheckConstants.CONF_API_HARD_TIMEOUT_DEFAULT_RESPONSE);
        property.setLabel("Hard Timeout Default Response is True (ON) or False (OFF)");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("When Timeout is reached, return True (ON) or False (OFF)");
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(ApiCheckConstants.CONF_API_HEADERS_PARAMETERS);
        property.setLabel("Headers to check");
        property.setType(ProviderConfigProperty.MAP_TYPE);
        property.setHelpText("ex : x-forwarded-for");
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(ApiCheckConstants.CONF_API_USERATTRS_PARAMETERS);
        property.setLabel("User Attributes to check");
        property.setType(ProviderConfigProperty.MAP_TYPE);
        property.setHelpText("ex : mail");
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(ApiCheckConstants.CONF_API_AUTHNOTES_PARAMETERS);
        property.setLabel("Auth Notes to check");
        property.setType(ProviderConfigProperty.MAP_TYPE);
        property.setHelpText("ex : requestreponse");
        configProperties.add(property);
    }

    @Override
    public Authenticator create(KeycloakSession session)
    {
        return new ApiCheckAuthenticator();
    }

    @Override
    public String getId()
    {
        return ID;
    }

    @Override
    public String getReferenceCategory()
    {
        return "OtpLogin";
    }

    @Override
    public boolean isConfigurable()
    {
        // return false;
        return true;
    }

    @Override
    public boolean isUserSetupAllowed()
    {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices()
    {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType()
    {
        return "Condition - API Check";
    }

    @Override
    public String getHelpText()
    {
        return "Condition - API Check";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public void init(Config.Scope config)
    {
        // not needed for current version
    }

    @Override
    public void postInit(KeycloakSessionFactory factory)
    {
        // not needed for current version
    }

    @Override
    public void close()
    {
        // not used for current version
    }

}