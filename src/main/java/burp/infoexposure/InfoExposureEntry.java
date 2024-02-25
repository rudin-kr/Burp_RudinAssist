package burp.infoexposure;

import burp.IHttpRequestResponseWithMarkers;

import java.net.URL;

public class InfoExposureEntry {
    final int index;                                        // Table Index
    final IHttpRequestResponseWithMarkers httpRequestResponse;  // Request and response
    final URL url;                                          // Request URL
    final String method;                                    // Method used in the request
    final StringBuilder search_result;
    final String pattern;
    final int count;
    final int respSize;                                     // Response Size(랙/lag 방지)

    InfoExposureEntry(int index, IHttpRequestResponseWithMarkers httpRequestResponse, URL url, String method, String pattern, StringBuilder search_result, int count, int respSize)
    {
        this.index = index;
        this.httpRequestResponse = httpRequestResponse;
        this.url = url;
        this.method = method;
        this.search_result = search_result;
        this.pattern = pattern;
        this.count = count;
        this.respSize = respSize;
    }
}
