FROM openjdk:21-jdk
ARG JAR_FILE=target/crdp_demo-0.0.1-SNAPSHOT.jar
COPY ${JAR_FILE} app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]