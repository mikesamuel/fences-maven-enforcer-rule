package com.example.client;

import com.example.api.*;

public class Roulette {
  public void pushAButton() {
    if (Math.random() < 0.02) {
      new Unsafe().pushRedButton();
    } else if (Math.random() < 0.02) {
      new Unsafe() {}.pushRedButton();  // An anonymous subclass.
    } else {
      new Safe().pushButton();
    }
  }
}
