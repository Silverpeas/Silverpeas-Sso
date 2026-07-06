FROM ubuntu:noble

ARG JAVA_VERSION=11
ARG MAVEN_VERSION=3.9.16
ARG GROOVY_VERSION=4.0.28
ARG NODEJS_VERSION=22

ARG USER=silveruser
ARG USER_GID=1001
ARG USER_UID=1001

RUN apt-get update && apt-get install -y \
    curl \
    git \
    gzip \
    openjdk-${JAVA_VERSION}-jdk \
    openjdk-${JAVA_VERSION}-doc \
    procps \
    sudo \
    tar \
    unzip \
    && curl -sL https://deb.nodesource.com/setup_${NODEJS_VERSION}.x | bash - \
    && apt-get install -y nodejs \
    && mkdir -p /opt \
    && curl -fsSL -o /tmp/apache-maven.tar.gz https://dlcdn.apache.org/maven/maven-3/${MAVEN_VERSION}/binaries/apache-maven-${MAVEN_VERSION}-bin.tar.gz \
    && tar -xzf /tmp/apache-maven.tar.gz -C /opt/ \
    && rm -f /tmp/apache-maven.tar.gz \
    && ln -s /opt/apache-maven-${MAVEN_VERSION}/bin/mvn /usr/bin/mvn \
    && curl -fsSL -o /tmp/apache-groovy.zip https://groovy.jfrog.io/artifactory/dist-release-local/groovy-zips/apache-groovy-binary-${GROOVY_VERSION}.zip \
    && unzip /tmp/apache-groovy.zip -d /opt/ \
    && rm -f /tmp/apache-groovy.zip \
    && echo `grep -oP '(?<=")[a-zA-Z:/]+(?=")' /etc/environment`:/opt/groovy-${GROOVY_VERSION}/bin > /etc/environment \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid ${USER_GID} ${USER} \
    && useradd --uid ${USER_UID} --gid ${USER_GID} -m ${USER} \
    && echo "${USER} ALL=\(root\) NOPASSWD:ALL" > /etc/sudoers.d/${USER} \
    && chmod 0440 /etc/sudoers.d/${USER}

ENV MAVEN_HOME=/opt/apache-maven-${MAVEN_VERSION}
ENV JAVA_HOME=/usr/lib/jvm/java-${JAVA_VERSION}-openjdk-amd64
ENV GROOVY_HOME=/opt/groovy-${GROOVY_VERSION}

USER $USER

CMD ["/bin/bash"]