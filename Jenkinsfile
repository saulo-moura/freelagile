#!/usr/bin/env groovy

node {   
    stage('Update Version' ) {
        checkout scm
	def version = sh(script: "cat VERSION | head -1 | tr -d '\n'", returnStdout: true)
        sh "sed -i -e \"s/\\(sonar.projectVersion=\\).*/\\1${version}/g\" sonar-project.properties"
    }

    stage('Scanner') {
        sh "sonar-scanner -Dsonar.login='${SONAR_TOKEN}'"
    }
}
