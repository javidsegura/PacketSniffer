#include <WiFi.h>

const char *ssid = "ESP32-Access-Point";
const char *password = "12345678";

void setup(){
  Serial.begin(115200);
  WiFi.mode(WIFI_AP);
  WiFi.softAP(ssid, password);

  Serial.println("Access Point Started");
  Serial.print("IP address: ");
  Serial.println(WiFi.softAPIP());
}

void loop(){

}