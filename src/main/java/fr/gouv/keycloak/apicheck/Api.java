package fr.gouv.keycloak.apicheck;

import java.io.IOException;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.keycloak.services.ServicesLogger;

public class Api
{
    /**
     * Sends call to api
     * 
     * @return string
     * @throws IOException
     * @throws ClientProtocolException
     */
   
    public Boolean postcheck(String rootUrl, String apiTokenid, String apiToken, String path, StringEntity data) throws ClientProtocolException, IOException
    {
        ServicesLogger.LOGGER.debug("CALL api = "+rootUrl+" POST path = "+path+" data = "+data);
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpPost request = new HttpPost(rootUrl + path);
        if (apiTokenid != null) {
            request.addHeader(apiTokenid, apiToken);
        }
        request.setEntity(data);
        HttpResponse response = httpClient.execute(request);
        return (response.getStatusLine().getStatusCode() == 200);
    }
}