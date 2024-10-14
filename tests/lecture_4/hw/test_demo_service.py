from pydantic import SecretStr
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from lecture_4.demo_service.api.main import create_app
from lecture_4.demo_service.core.users import (
    UserRole,
    UserInfo,
    UserEntity,
    UserService,
    password_is_longer_than_8,
)
from lecture_4.demo_service.api.contracts import (
    UserAuthRequest,
    UserResponse,
    RegisterUserRequest,
)

app = create_app()
client = TestClient(app)

TEST_PASSWORD = "testPassword"
TEST_USERNAME = "testUsername"
TEST_NAME = "testName"
TEST_BIRTHDATE = datetime.now()


@pytest.fixture()
def user_info():
    """
    Fixture to generate a test UserInfo object with a valid username and password.
    """
    return UserInfo(
        username=TEST_USERNAME,
        name=TEST_NAME,
        birthdate=TEST_BIRTHDATE,
        role=UserRole.USER,
        password=SecretStr(TEST_PASSWORD),
    )


@pytest.fixture()
def user_entity(user_info: UserInfo):
    """
    Fixture to create a user entity instance.

    Args:
        user_info (UserInfo): The user info to use for the user entity.

    Returns:
        UserEntity: The user entity instance.
    """
    return UserEntity(
        uid=1,
        info=user_info,
    )


@pytest.fixture()
def user_service():
    """
    Fixture to create a user service instance.

    Returns:
        UserService: The user service instance.
    """
    return UserService()


@pytest.fixture
def register_user_request():
    """
    Fixture to generate a test RegisterUserRequest object with a valid username and password.
    """
    return RegisterUserRequest(
        username=TEST_USERNAME,
        name=TEST_NAME,
        birthdate=TEST_BIRTHDATE,
        password=SecretStr(TEST_PASSWORD),
    )


@pytest.fixture()
def user_response():
    """
    Fixture to generate a test UserResponse object with a valid username and password.
    """
    return UserResponse(
        uid=1,
        username=TEST_USERNAME,
        name=TEST_NAME,
        birthdate=TEST_BIRTHDATE,
        role=UserRole.USER,
    )


@pytest.fixture()
def user_authorisation_request():
    """
    Fixture to generate a test UserAuthRequest object with a valid username and password.
    """
    return UserAuthRequest(username=TEST_USERNAME, password=SecretStr(TEST_PASSWORD))


def test_successfull_creation():
    """
    Ensures that the app can be successfully created.
    """
    assert app is not None


def test_user_role():
    """
    Verifies that the UserRole enum has the correct values.
    """
    user = UserRole.USER
    admin = UserRole.ADMIN
    assert user == UserRole.USER
    assert admin == UserRole.ADMIN


def test_user_info(user_info: UserInfo):
    assert user_info.username == TEST_USERNAME
    assert user_info.name == TEST_NAME
    assert user_info.birthdate == TEST_BIRTHDATE
    assert user_info.role == UserRole.USER
    assert user_info.password == SecretStr(TEST_PASSWORD)


def test_user_entity(user_entity: UserEntity):
    assert user_entity.uid == 1
    assert user_entity.info.username == TEST_USERNAME
    assert user_entity.info.name == TEST_NAME
    assert user_entity.info.birthdate == TEST_BIRTHDATE
    assert user_entity.info.role == UserRole.USER
    assert user_entity.info.password == SecretStr(TEST_PASSWORD)


def test_user_service(user_service: UserService, user_info: UserInfo):
    user_entity_instance = user_service.register(user_info)
    assert user_entity_instance.info.username == user_info.username
    assert user_entity_instance.info.name == user_info.name
    assert user_entity_instance.info.birthdate == user_info.birthdate
    assert user_entity_instance.info.role == user_info.role
    assert user_entity_instance.info.password == user_info.password

    assert user_service.get_by_username(user_info.username) == user_entity_instance
    assert user_service.get_by_id(user_entity_instance.uid) == user_entity_instance

    with pytest.raises(ValueError):
        user_service.grant_admin(2)

    user_service.grant_admin(user_entity_instance.uid)
    assert user_entity_instance.info.role == UserRole.ADMIN


def test_password_is_longer_than_8():
    """
    Verifies that the password_is_longer_than_8 function works correctly.
    """
    assert not password_is_longer_than_8("01234567")
    assert password_is_longer_than_8("012345678")


def test_register_user_request(register_user_request: RegisterUserRequest):
    assert register_user_request.username == TEST_USERNAME
    assert register_user_request.name == TEST_NAME
    assert register_user_request.birthdate == TEST_BIRTHDATE
    assert register_user_request.password == SecretStr(TEST_PASSWORD)


def test_user_response(user_response: UserResponse, user_entity: UserEntity):
    assert user_response.uid == 1
    assert user_response.username == TEST_USERNAME
    assert user_response.name == TEST_NAME
    assert user_response.birthdate == TEST_BIRTHDATE
    assert user_response.role == UserRole.USER

    user_response_from_entity = UserResponse.from_user_entity(user_entity)
    assert user_response_from_entity.uid == 1
    assert user_response_from_entity.username == TEST_USERNAME
    assert user_response_from_entity.name == TEST_NAME
    assert user_response_from_entity.birthdate == TEST_BIRTHDATE
    assert user_response_from_entity.role == UserRole.USER


def test_user_auth_request(user_authorisation_request: UserAuthRequest):
    assert user_authorisation_request.username == TEST_USERNAME
    assert user_authorisation_request.password == SecretStr(TEST_PASSWORD)
