FROM golang:alpine AS build-gateway
LABEL maintainer Ascensio System SIA <support@onlyoffice.com>
WORKDIR /usr/src/app
COPY . .
RUN go build services/gateway/main.go

FROM golang:alpine AS build-auth
LABEL maintainer Ascensio System SIA <support@onlyoffice.com>
WORKDIR /usr/src/app
COPY . .
RUN go build services/auth/main.go

FROM golang:alpine AS build-callback
LABEL maintainer Ascensio System SIA <support@onlyoffice.com>
WORKDIR /usr/src/app
COPY . .
RUN go build services/callback/main.go

FROM golang:alpine AS gateway
WORKDIR /usr/src/app
RUN apk update && \
    apk add python3 && \
    apk add py3-pip && \
    pip install requests kubernetes --break-system-packages
COPY --from=build-gateway \
     /usr/src/app/main \
     /usr/src/app/main
EXPOSE 4044
CMD ["./main", "server"]

FROM golang:alpine AS auth
WORKDIR /usr/src/app
RUN apk update && \
    apk add python3 && \
    apk add py3-pip && \
    pip install requests kubernetes --break-system-packages
COPY --from=build-auth \
     /usr/src/app/main \
     /usr/src/app/main
EXPOSE 5069
CMD ["./main", "server"]

FROM golang:alpine AS callback
WORKDIR /usr/src/app
RUN apk update && \
    apk add python3 && \
    apk add py3-pip && \
    pip install requests kubernetes --break-system-packages
COPY --from=build-callback \
     /usr/src/app/main \
     /usr/src/app/main
EXPOSE 5044
CMD ["./main", "server"]
