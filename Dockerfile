# 🔹 Folosim OpenJDK 21 pentru a construi aplicația
FROM openjdk:21-jdk-slim

# 🔹 Setăm directorul de lucru
WORKDIR /app

# 🔹 Copiem și descărcăm dependențele Maven (pentru caching)
COPY pom.xml mvnw ./
COPY .mvn .mvn
RUN chmod +x mvnw && ./mvnw dependency:go-offline

# 🔹 Copiem codul sursă în container
COPY src ./src

# 🔹 Construim fișierul `.war`
RUN ./mvnw clean package -DskipTests

# 🔹 Creăm un utilizator non-root pentru securitate
RUN useradd -m springuser

# 🔹 Setăm directorul de lucru
WORKDIR /app

# 🔹 Setăm proprietarul fișierelor la utilizatorul non-root
USER springuser

# 🔹 Expunem portul pe care va rula aplicația
EXPOSE 8081

# 🔹 Definim punctul de intrare
CMD ["java", "-jar", "target/secure-owasp-be-0.0.1-SNAPSHOT.war"]