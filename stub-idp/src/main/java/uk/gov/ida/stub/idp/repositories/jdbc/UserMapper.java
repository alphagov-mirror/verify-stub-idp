package uk.gov.ida.stub.idp.repositories.jdbc;

import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.ida.stub.idp.domain.DatabaseIdpUser;
import uk.gov.ida.stub.idp.repositories.jdbc.json.IdpUserJson;

import javax.inject.Singleton;

import static uk.gov.ida.stub.idp.utils.Exceptions.uncheck;

@Singleton
public class UserMapper {

    private final ObjectMapper mapper;

    public UserMapper(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public User mapFrom(String idpFriendlyName, DatabaseIdpUser idpUser) {
        String idpUserAsJson = uncheck(() -> mapper.writeValueAsString(idpUser));

        return new User(
            null,
            idpUser.getUsername(),
            idpUser.getPassword(),
            idpFriendlyName,
            idpUserAsJson
        );
    }

    public DatabaseIdpUser mapToIdpUser(User user) {
        IdpUserJson idpUserJson = uncheck(() -> mapper.readValue(user.getData(), IdpUserJson.class));

        return new DatabaseIdpUser(
            idpUserJson.getUsername(),
            idpUserJson.getPersistentId(),
            idpUserJson.getPassword(),
            idpUserJson.getFirstnames(),
            idpUserJson.getMiddleNames(),
            idpUserJson.getSurnames(),
            idpUserJson.getGender(),
            idpUserJson.getDateOfBirths(),
            idpUserJson.getAddresses(),
            idpUserJson.getLevelOfAssurance()
        );
    }

}
