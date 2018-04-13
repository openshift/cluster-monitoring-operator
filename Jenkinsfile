pipeline {
    agent {
        label 'docker && team-monitoring'
    }

    options {
      timestamps()
      buildDiscarder(logRotator(numToKeepStr:'20', artifactNumToKeepStr: '20'))
    }



    stages {
        stage('generate-assets') {
            agent {
                dockerfile {
                    dir 'scripts/jenkins/crossbuild-env'
                    args '-u root -v /var/run/docker.sock:/var/run/docker.sock'
                    label 'docker && team-monitoring'
                }
            }
            steps {
                sh('''
                    make generate
                    git diff --exit-code
                ''')
            }
            post {
                failure {
                    slackNotify("generate-assets")
                }
            }
        }



        stage('build-image') {
            agent {
                dockerfile {
                    dir 'scripts/jenkins/crossbuild-env'
                    args '-u root -v /var/run/docker.sock:/var/run/docker.sock'
                    label 'docker && team-monitoring'
                }
            }
            steps {
                sh('''
                    mkdir -p /go/src/github.com/coreos-inc
                    ln -s $PWD /go/src/github.com/openshift/cluster-monitoring-operator
                    make crossbuild
                ''')
                withCredentials([
                        usernamePassword(
                            credentialsId: 'coreos-prometheus-operator-ci',
                            passwordVariable: 'QUAY_ROBOT_SECRET',
                            usernameVariable: 'QUAY_ROBOT_USERNAME'
                        )
                    ]) {
                    sh('''
                          docker build -t quay.io/coreos/cluster-monitoring-operator-dev:$BUILD_ID .
                          docker login -u="$QUAY_ROBOT_USERNAME" -p="$QUAY_ROBOT_SECRET" quay.io
                          docker push quay.io/coreos/cluster-monitoring-operator-dev:$BUILD_ID
                    ''')
                }
            }
            post {
                failure {
                    slackNotify("build-image")
                }
            }
        }



        stage('build-and-push-test-image') {
            agent {
                dockerfile {
                    dir 'scripts/jenkins/crossbuild-env'
                    args '-u root -v /var/run/docker.sock:/var/run/docker.sock'
                    label 'docker && team-monitoring'
                }
            }
            steps {
                sh('''
                    mkdir -p /go/src/github.com/coreos-inc
                    ln -s $PWD /go/src/github.com/openshift/cluster-monitoring-operator
                ''')
                withCredentials([
                        usernamePassword(
                            credentialsId: 'coreos-prometheus-operator-ci',
                            passwordVariable: 'QUAY_ROBOT_SECRET',
                            usernameVariable: 'QUAY_ROBOT_USERNAME'
                        )
                    ]) {
                    sh('''
                        export TAG=`git rev-parse --short HEAD`
                        make build-docker-test
                        docker login -u="$QUAY_ROBOT_USERNAME" -p="$QUAY_ROBOT_SECRET" quay.io
                        docker push quay.io/coreos/cluster-monitoring-operator-test:$TAG

                        if [ "$BRANCH_NAME" = "master" ]
                        then
				docker tag quay.io/coreos/cluster-monitoring-operator-test:$TAG quay.io/coreos/cluster-monitoring-operator-test:master
				docker push quay.io/coreos/cluster-monitoring-operator-test:master
                        fi
                    ''')
                }
            }
            post {
                failure {
                    slackNotify("build-and-push-test-image")
                }
            }
        }



        stage('e2e') {
            agent {
                label 'docker && team-monitoring'
            }
            environment {
                PLATFORM = 'aws'
                AWS_REGION = 'eu-west-2'
            }
            steps {
                withCredentials([
                    [
                        $class: 'AmazonWebServicesCredentialsBinding',
                        credentialsId: 'aws-teammonitoring-jenkins-user',
                        accessKeyVariable: 'AWS_ACCESS_KEY_ID',
                        secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
                    ],
                ]) {
                    sshagent (credentials: ['jenkins-tpo-ssh-key']) {
                        sh("./scripts/jenkins/start-k8s-cluster.sh")
                    }
                }
                withCredentials([string(credentialsId: 'coreos_prometheus_operator_ci_pull_secret', variable: 'PULL_SECRET')]) {
                    sh('./scripts/jenkins/run-e2e-tests.sh')
                }
            }
            post {
                always {
                    archiveArtifacts allowEmptyArchive: true, artifacts: 'build/**/terraform.tfstate'
                    withCredentials([
                        [
                            $class: 'AmazonWebServicesCredentialsBinding',
                            credentialsId: 'aws-teammonitoring-jenkins-user',
                            accessKeyVariable: 'AWS_ACCESS_KEY_ID',
                            secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
                        ],
                    ]) {
                        sshagent (credentials: ['jenkins-tpo-ssh-key']) {
                            script {
                                try {
                                    sh('''
                                        ./scripts/jenkins/stop-k8s-cluster.sh
                                    ''')
                                } catch (error) {
                                    slackNotify('@mxinden destroying cluster')
                                    throw error
                                }
                            }
                        }
                    }
                }

                failure {
                    // Only send notifications for builds of master.
                    script {
                        if (env.BRANCH_NAME == 'master') {
                            slackNotify("e2e")
                        }
                    }
                }
            }
        }
    }
}



def slackNotify(stage) {
    def link  = "<${env.RUN_DISPLAY_URL}|#${env.BUILD_NUMBER}>"
    def msg = "Cluster Monitoring Operator ${stage} failed (${link})"

    slackSend(channel: '#team-monitoring', color: 'danger', message: msg, teamDomain: 'coreos', tokenCredentialId: 'team-monitoring-slack-jenkins')
}
