package burp.reflectedXSS;

import burp.IHttpRequestResponseWithMarkers;

import java.net.URL;
import java.util.List;

public class ReflectedXSSEntry {
    final int index;                                        // Table Index
    final IHttpRequestResponseWithMarkers httpRequestResponse;  // Request and response
    final URL url;                                          // Request URL
    final String method;                                    // Method used in the request
    final int howmany;                                      // Count
    final List<String[]> doubted_params;                    // Doubted Parameter as Vulnerability
    final String respHeaderMame;                            // Response Header Mame(Content-Type)
    final String respBodyMame;                              // Response Body Type
    final int respSize;                                     // Response Size(랙/lag 방지)

    ReflectedXSSEntry(int index, IHttpRequestResponseWithMarkers httpRequestResponse, List<String[]> doubted_params, URL url, String method, String headerMimeType, String bodyMimeType, int howmany, int respSize)
    {
        this.index = index;
        this.httpRequestResponse = httpRequestResponse;
        this.doubted_params = doubted_params;
        this.url = url;
        this.method = method;
        this.respHeaderMame = headerMimeType;
        this.respBodyMame = bodyMimeType;
        this.howmany = howmany;
        this.respSize = respSize;
    }
}
