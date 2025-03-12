# Folosim OpenJDK 21 pentru a construi aplicatia
FROM openjdk:21-jdk-slim

# Setam directorul de lucru
WORKDIR /app

# Copiem si descarcam dependentele Maven
COPY pom.xml mvnw ./
COPY .mvn .mvn
RUN chmod +x mvnw && ./mvnw dependency:go-offline

# Copiem codul sursa în container
COPY src ./src

# Construim fisierul `.war`
RUN ./mvnw clean package -DskipTests

# Cream un utilizator non-root pentru securitate
RUN useradd -m springuser

# Setam directorul de lucru
WORKDIR /app

# Setam proprietarul fisierelor la utilizatorul non-root
USER springuser

# Expunem portul pe care va rula aplicatia
EXPOSE 8081

# Definim punctul de intrare
CMD ["java", "-jar", "target/secure-owasp-be-0.0.1-SNAPSHOT.war"]