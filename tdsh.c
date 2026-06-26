#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>

int main(int argc, char *argv[]) {

  if (argc < 2) {
    printf("Error: Missing arguments.\n");
    printf("Usage: %s <argument>\n", argv[0]);
    return 1;
  }

  // Safe to access argv[1] now
  printf("First argument: %s\n", argv[1]);

	WSADATA wsaData;
	int iResult;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
	if (iResult != 0) {
	    printf("WSAStartup failed: %d\n", iResult);
	    return 1;
	}

	struct addrinfo *result = NULL,
	                *ptr = NULL,
  	              hints;

	ZeroMemory( &hints, sizeof(hints) );
	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	#define DEFAULT_PORT "2604"

	// Resolve the server address and port
	iResult = getaddrinfo(argv[1], DEFAULT_PORT, &hints, &result);
	if (iResult != 0) {
	    printf("getaddrinfo failed: %d\n", iResult);
	    WSACleanup();
	    return 1;
	}

	SOCKET ConnectSocket = INVALID_SOCKET;

	// Attempt to connect to the first address returned by
	// the call to getaddrinfo
	ptr=result;

	// Create a SOCKET for connecting to server
	ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, 
	    ptr->ai_protocol);

	if (ConnectSocket == INVALID_SOCKET) {
	    printf("Error at socket(): %d\n", WSAGetLastError());
	    freeaddrinfo(result);
	    WSACleanup();
	    return 1;
	}


	// Connect to server.
	iResult = connect( ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
	    closesocket(ConnectSocket);
	    ConnectSocket = INVALID_SOCKET;
	}

	// Should really try the next address returned by getaddrinfo
	// if the connect call failed
	// But for this simple example we just free the resources
	// returned by getaddrinfo and print an error message

	freeaddrinfo(result);

	if (ConnectSocket == INVALID_SOCKET) {
	    printf("Unable to connect to server!\n");
	    WSACleanup();
	    return 1;
	}

	#define DEFAULT_BUFLEN 512

	int recvbuflen = DEFAULT_BUFLEN;

	const char *sendbuf = "this is a test";
	char recvbuf[DEFAULT_BUFLEN];

	// Send an initial buffer
	iResult = send(ConnectSocket, sendbuf, (int) strlen(sendbuf), 0);
	if (iResult == SOCKET_ERROR) {
	    printf("send failed: %d\n", WSAGetLastError());
	    closesocket(ConnectSocket);
	    WSACleanup();
	    return 1;
	}

	printf("Bytes Sent: %d\n", iResult);

	// shutdown the connection for sending since no more data will be sent
	// the client can still use the ConnectSocket for receiving data
	iResult = shutdown(ConnectSocket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
	    printf("shutdown failed: %d\n", WSAGetLastError());
	    closesocket(ConnectSocket);
	    WSACleanup();
	    return 1;
	}

	// Receive data until the server closes the connection
	do {
	    iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
	    if (iResult > 0)
	        printf("Bytes received: %d\n", iResult);
	    else if (iResult == 0)
	        printf("Connection closed\n");
	    else
	        printf("recv failed: %d\n", WSAGetLastError());
	} while (iResult > 0);

  return 0;
}