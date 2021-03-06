import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

public class PostDemo {
    public static void main(String[] args) {
	try {
	    URL url = new URL("http://192.1.1.1:4243/v1.37/containers/create?name=demo");
	    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
	    conn.setDoOutput(true);
	    conn.setRequestMethod("POST");
	    conn.setRequestProperty("Content-Type", "application/json");

	    String input = "{\"Image\": \"busybox\", \"Cmd\": [\"/bin/sh\"], \"NetworkDisabled\": true, \"HostConfig\": {\"AutoRemove\": true}, \"Tty\": true}";

	    OutputStream os = conn.getOutputStream();
	    os.write(input.getBytes());
	    os.flush();

	    if (conn.getResponseCode() != HttpURLConnection.HTTP_CREATED) {
		throw new RuntimeException("Failed : HTTP error code : "+conn.getResponseCode());
	    }

	    BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));

	    String output;
	    System.out.println("Output from Server .... \n");
	    while ((output=br.readLine())!=null) {
		System.out.println(output);
	    }

	    conn.disconnect();

	} catch (MalformedURLException e) {
	    e.printStackTrace();
	} catch (IOException e) {
	    e.printStackTrace();
	}
    }
}
