FROM qa.stratio.com/stratio/java-microservice-dockerbase:2.0.1

ADD target/*.jar app.jar
ADD src/main/resources/ci/entrypoint.sh entrypoint.sh

RUN touch /data/app.jar && \
    chmod +x /data/entrypoint.sh


ENTRYPOINT ["bash", "/data/entrypoint.sh" ]