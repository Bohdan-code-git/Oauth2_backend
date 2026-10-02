FROM node:22-alpine AS frontend
WORKDIR /repo
COPY OAuth/OAuth/package.json OAuth/OAuth/package-lock.json ./OAuth/OAuth/
RUN npm --prefix OAuth/OAuth ci
COPY OAuth/OAuth/ ./OAuth/OAuth/
RUN npm --prefix OAuth/OAuth run build -- --configuration production

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY Oauth2_backend/Oauth2_backend.csproj Oauth2_backend/
RUN dotnet restore Oauth2_backend/Oauth2_backend.csproj
COPY Oauth2_backend/ Oauth2_backend/
COPY --from=frontend /repo/OAuth/OAuth/dist/Switchboard/browser/ Oauth2_backend/wwwroot/
RUN dotnet publish Oauth2_backend/Oauth2_backend.csproj -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "Oauth2_backend.dll"]
