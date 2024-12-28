pipeline {
    agent any

    environment {
        REPO_URL = 'https://github.com/UmerGulzar223/flask-app.git'
    }

    stages {
        stage('Clone Repository') {
            steps {
                // Clone the repository
                git url: "${REPO_URL}", branch: 'main'
            }
        }

        stage('Install Dependencies') {
            steps {
                // Install dependencies in a virtual environment
                sh '''
                python3 --version || python --version
                python3 -m venv venv || python -m venv venv
                source venv/bin/activate
                pip install --upgrade pip
                pip install -r requirements.txt
                '''
            }
        }

        stage('Run Unit Tests') {
            steps {
                // Run unit tests with pytest
                sh '''
                source venv/bin/activate
                pytest --junitxml=report.xml
                '''
            }
        }
    }

    post {
        always {
            echo 'Pipeline completed!'
        }
        success {
            echo 'Pipeline succeeded!'
        }
        failure {
            echo 'Pipeline failed!'
        }
        unstable {
            echo 'Pipeline is unstable (e.g., test failures).'
        }
    }
}
