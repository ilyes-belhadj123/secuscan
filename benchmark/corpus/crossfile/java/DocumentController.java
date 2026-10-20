package com.acme.documents;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// Benchmark : entrée utilisateur transmise aux méthodes d'une autre classe (vulnérable).
public class DocumentController extends HttpServlet {
    private final DocumentStore store = new DocumentStore();

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        byte[] content = store.readDocument(name);
        response.getOutputStream().write(content);
        store.mirrorRemote(request.getParameter("source"));
    }
}
