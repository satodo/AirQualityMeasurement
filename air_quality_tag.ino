#include <SPI.h>
#include <MFRC522.h>
#include "Adafruit_CCS811.h"

#define SS_PIN 10
#define RST_PIN 9

// Your GitHub Pages address without https://, ending in ?
const char SITE[] = "yourusername.github.io/air/?";

MFRC522 rfid(SS_PIN, RST_PIN);
Adafruit_CCS811 ccs;
MFRC522::MIFARE_Key ndefKey;

uint16_t lastCo2 = 400;
uint16_t lastTvoc = 0;

// Writes a web link to a Mifare Classic card that has already been
// formatted for links (write one with NFC Tools first).
// Only data blocks are written, never the key blocks.
bool writeNdefUrl(const char *url) {
  byte data[96];
  size_t urlLen = strlen(url);
  size_t recordLen = urlLen + 5;
  size_t total = recordLen + 3;

  if (total > sizeof(data)) {
    Serial.println("Link too long for this card");
    return false;
  }

  memset(data, 0, sizeof(data));
  data[0] = 0x03;               // NDEF message marker
  data[1] = recordLen;          // message length
  data[2] = 0xD1;               // single record, well-known type
  data[3] = 0x01;               // type length
  data[4] = urlLen + 1;         // payload length
  data[5] = 0x55;               // type: URI
  data[6] = 0x04;               // prefix: https://
  memcpy(&data[7], url, urlLen);
  data[7 + urlLen] = 0xFE;      // end marker

  byte block = 4;
  for (size_t offset = 0; offset < total; offset += 16, block++) {
    if ((block + 1) % 4 == 0) block++;   // skip key blocks (7, 11, ...)

    if (block % 4 == 0) {                // first block of a sector
      MFRC522::StatusCode auth = rfid.PCD_Authenticate(
        MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &ndefKey, &(rfid.uid));
      if (auth != MFRC522::STATUS_OK) {
        Serial.println("Could not unlock the card. Write a link to it once with NFC Tools first.");
        return false;
      }
    }

    MFRC522::StatusCode st = rfid.MIFARE_Write(block, &data[offset], 16);
    if (st != MFRC522::STATUS_OK) {
      Serial.println("Write failed");
      return false;
    }
  }
  return true;
}

void setup() {
  Serial.begin(9600);
  SPI.begin();
  rfid.PCD_Init();

  byte keyBytes[6] = {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7};
  for (byte i = 0; i < 6; i++) ndefKey.keyByte[i] = keyBytes[i];

  if (!ccs.begin()) {
    Serial.println("Sensor not found, check wiring");
    while (1);
  }
  while (!ccs.available());
  Serial.println("Ready. Tap a card on the reader.");
}

void loop() {
  if (ccs.available() && !ccs.readData()) {
    lastCo2 = ccs.geteCO2();
    lastTvoc = ccs.getTVOC();
  }

  if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial()) return;

  char url[64];
  snprintf(url, sizeof(url), "%sc=%u&v=%u", SITE, lastCo2, lastTvoc);

  if (writeNdefUrl(url)) {
    Serial.print("Written: https://");
    Serial.println(url);
  }

  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();
  delay(1500);
}
