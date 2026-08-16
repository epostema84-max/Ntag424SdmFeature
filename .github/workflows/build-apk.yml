name: APK bouwen

on:
  workflow_dispatch:        # handmatig starten via de knop Run workflow
  push:
    branches: [master, main]

jobs:
  bouwen:
    runs-on: ubuntu-latest
    steps:
      - name: Broncode ophalen
        uses: actions/checkout@v4

      - name: Java 17 installeren
        uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: '17'

      - name: Gradle wrapper uitvoerbaar maken
        run: chmod +x ./gradlew

      - name: Debug-APK bouwen
        run: ./gradlew assembleDebug --no-daemon --stacktrace

      - name: APK klaarzetten om te downloaden
        uses: actions/upload-artifact@v4
        with:
          name: klok-tagwriter
          path: app/build/outputs/apk/debug/*.apk
          if-no-files-found: error
