package burp.authcheck;

import burp.IHttpRequestResponseWithMarkers;

import java.net.URL;

public class AuthCheckEntry {
    final int index;                                        // Table Index
    final IHttpRequestResponseWithMarkers orgRequestResponse;  // Request and response
    final byte[] editedRequest;
    final byte[] editedResponse;
    final URL url;                                          // Request URL
    final String method;                                    // Method used in the request
    final String session;
    final String compare_result;
    final int respSize;                                     // Response Size(랙/lag 방지)

    AuthCheckEntry(int index, IHttpRequestResponseWithMarkers orgRequestResponse, byte[] editedRequest, byte[] editedResponse, URL url, String method, String session, String compare_result, int respSize)
    {
        this.index = index;
        this.orgRequestResponse = orgRequestResponse;
        this.editedRequest = editedRequest;
        this.editedResponse = editedResponse;
        this.url = url;
        this.method = method;
        this.session = session;
        this.compare_result = compare_result;
        this.respSize = respSize;
    }
}
