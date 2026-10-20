package com.acme.documents;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// Benchmark : mêmes appels entre classes, avec des valeurs converties en nombres (aucune alerte attendue).
public class InvoiceController extends HttpServlet {
    private final InvoiceStore store = new InvoiceStore();

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        long id = Long.parseLong(request.getParameter("id"));
        response.getOutputStream().write(store.readInvoice(id));
        store.mirrorProduct(Long.parseLong(request.getParameter("product")));
    }
}
