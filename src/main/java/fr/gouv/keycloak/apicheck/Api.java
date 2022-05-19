package fr.gouv.keycloak.apicheck;

import java.io.IOException;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import java.util.TimerTask;
import java.util.Timer;
import org.jboss.logging.Logger;

public class Api
{
    /**
     * Sends call to api
     * 
     * @return string
     * @throws IOException
     * @throws ClientProtocolException
     */
    
    private static Logger logger = Logger.getLogger(ApiCheckAuthenticator.class);

    public Boolean postcheck(String rootUrl, String apiTokenid, String apiToken, String path, StringEntity data, int hardTimeout) throws ClientProtocolException, IOException
    {
        String msg = "CALL api = "+rootUrl+" POST path = "+path;
        logger.debug(msg);
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpPost request = new HttpPost(rootUrl + path);
        if (apiTokenid != null) {
            request.addHeader(apiTokenid, apiToken);
        }
        request.setEntity(data);

        // hardTimeout
        TimerTask task = new TimerTask() {
            @Override
            public void run() {
                if (request != null) {
                    request.abort();
                    logger.warn(msg + " : hardTimeout reached");
                }
            }
        };
        new Timer(true).schedule(task, hardTimeout * 1000);

        HttpResponse response = httpClient.execute(request);
        return (response.getStatusLine().getStatusCode() == 200);
    }
}