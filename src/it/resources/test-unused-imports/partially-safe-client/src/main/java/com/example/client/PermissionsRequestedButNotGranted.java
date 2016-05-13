package com.example.client;

import com.example.api.Unsafe;

public class PermissionsRequestedButNotGranted {
  public void launch() {
    System.err.println("You have to the count of 10 to get clear.");
    new Unsafe().pushRedButton();
  }
}
