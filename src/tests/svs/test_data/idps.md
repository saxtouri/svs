{
  "idp_post": {
    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST": [
      {
        "location": "https://example.com/post" 
      }
    ]
  },
  "idp_redirect": {
    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect": [
      {
        "location": "https://example.com/redirect" 
      }
    ]
  },
  "idp_post_redirect": {
    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect": [
      {
        "location": "https://example.com/redirect" 
      }
    ],
    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST": [
      {
        "location": "https://example.com/redirect" 
      }
    ]
  }
}