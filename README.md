# Nancy.KeyRockAuthenticationProvider

It's a provider for [SimpleAuthentication](https://github.com/SimpleAuthentication/SimpleAuthentication)

## KeyRock?

Everything you need to know about KeyRock is in the [Fiware Catalogue Page](http://catalogue.fiware.org/enablers/identity-management-keyrock) :)

Here is the [Repo in Github](https://github.com/ging/fi-ware-idm)

## Configuration

Since you can host your own instace of KeyRock we can not have the urls fixed in the code, so you have to add the urls in your web.config

```xml
<keyRock>
    <urls baseUrl="http://localhost:9998/" authenticationRedirectionUrl="http://localhost:9998/oauth2/authorize"/>
</keyRock>
```

## Nuget