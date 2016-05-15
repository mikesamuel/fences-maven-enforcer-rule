package com.example.client;

import com.example.api.*;

public class Roulette {
  public void pushAButton() {
    if (Math.random() < 0.02) {
      new Unsafe().pushRedButton().pushRedButton();
    } else if (Math.random() < 0.02) {
      // Two calls on an anonymous subclass, each banned.
      new Unsafe() {}.pushRedButton();
    } else {
      new Safe().pushButton();
    }
  }
}
