#! /bin/bash

APP_NAME=traefik-gateway-plugin

AWS_REGION="eu-west-1"
REGISTRY_ID=$(aws ecr describe-registry --output text --query 'registryId' --region $AWS_REGION)
REGISTRY="${REGISTRY_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
REPO_PREFIX=file-convert/app
DOCKERFILE=Dockerfile
BASE_IMAGE=gcr.io/distroless/base-debian12

TARGET_ARCH=linux/amd64,linux/arm64

set -e

TAG=$(git rev-parse --short HEAD --)
echo "Tag: ${TAG}"

# echo "==== Building GoLang binary ====
echo "==== Build and push Docker image ====" 
aws ecr describe-repositories --region $AWS_REGION --repository-names ${REPO_PREFIX}/${APP_NAME} || aws ecr create-repository --repository-name ${REPO_PREFIX}/${APP_NAME} --region $AWS_REGION 
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $REGISTRY
docker buildx build \
    --push \
    --platform $TARGET_ARCH \
    --build-arg APP_NAME=${APP_NAME} \
    --build-arg BASE_IMAGE=${BASE_IMAGE} \
    -t ${REGISTRY}/${REPO_PREFIX}/${APP_NAME}:${TAG} \
    -f Dockerfile \
    .

echo "Replace the tag in the /storage/WorkspaceFileConvert/k8s_live_infra/AWS/eu-west-1/infra/ingress/traefik/values.yaml file with ${TAG}"