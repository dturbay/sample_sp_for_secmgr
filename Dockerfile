FROM openjdk:8-jdk-alpine AS BUILD

ENV BUILD_APP_DIR=/usr/src/myapp

COPY ./core ${BUILD_APP_DIR}/core
COPY ./build.gradle ${BUILD_APP_DIR}
COPY ./gradlew ${BUILD_APP_DIR}
COPY ./settings.gradle ${BUILD_APP_DIR}
COPY ./gradle.properties ${BUILD_APP_DIR}
COPY ./samples ${BUILD_APP_DIR}/samples
#COPY ./src ${BUILD_APP_DIR}/src
COPY ./gradle ${BUILD_APP_DIR}/gradle


RUN apk update && apk add bash
RUN cd ${BUILD_APP_DIR} \
	&& ./gradlew bootJar


FROM openjdk:8-jre-alpine

ENV APP_NAME=spring-security-saml-simple-service-provider-2.0.0.BUILD-SNAPSHOT.jar

COPY --from=BUILD /usr/src/myapp/samples/boot/simple-service-provider/build/libs/${APP_NAME} /opt/

COPY ./secmgr1.crt /usr/local/share/ca-certificates/secmgr1.crt
RUN update-ca-certificates
RUN keytool -noprompt -import -alias secmgr1 -file /usr/local/share/ca-certificates/secmgr1.crt -keystore cacerts -storepass changeit


EXPOSE 8088

CMD ["sh", "-c", "java -jar /opt/${APP_NAME}"]


