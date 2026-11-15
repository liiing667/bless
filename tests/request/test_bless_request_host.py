import pytest
from bless.config.bless_config import HOSTNAME_VALIDATION_OPTION
from bless.request.bless_request_host import HOSTNAME_VALIDATION_OPTIONS, BlessHostSchema, validate_hostname
from marshmallow import ValidationError


@pytest.mark.parametrize("test_input", [
    'thisthat',
    'this.that',
    '10.1.1.1'
])
def test_validate_hostnames(test_input):
    validate_hostname(test_input, HOSTNAME_VALIDATION_OPTIONS.url)


@pytest.mark.parametrize("test_input", [
    'this..that',
    ['thisthat'],
    'this!that.com'
])
def test_invalid_hostnames(test_input):
    with pytest.raises(ValidationError) as e:
        validate_hostname(test_input, HOSTNAME_VALIDATION_OPTIONS.url)
    assert str(e.value) == 'Invalid hostname "ssh://{}".'.format(test_input)


@pytest.mark.parametrize("test_input", [
    'this..that',
    ['thisthat'],
    'this!that.com',
    'this,that'
])
def test_invalid_hostnames_with_disabled(test_input):
    validate_hostname(test_input, HOSTNAME_VALIDATION_OPTIONS.disabled)


@pytest.mark.parametrize("test_input", [
    'thisthat,this.that,10.1.1.1',
    'this.that,thishostname'
])
def test_valid_multiple_hostnames(test_input):
    BlessHostSchema().validate_hostnames(test_input)


@pytest.mark.parametrize("test_input", [
    'thisthat, this.that',
])
def test_invalid_multiple_hostnames(test_input):
    with pytest.raises(ValidationError) as e:
        BlessHostSchema().validate_hostnames(test_input)
    assert str(e.value) == 'Invalid hostname "ssh:// this.that".'


@pytest.mark.parametrize("test_input", [
    'thisthat,thisthat',
    'this.that,thisthat,this.that',
])
def test_invalid_multiple_hostnames_with_duplicates(test_input):
    with pytest.raises(ValidationError) as e:
        BlessHostSchema().validate_hostnames(test_input)
    assert str(e.value) == 'Duplicate hostnames are not allowed.'


@pytest.mark.parametrize("test_input", [
    '',
    ',',
    'thisthat,',
    'thisthat,,this.that',
])
def test_invalid_multiple_hostnames_with_empty(test_input):
    schema = BlessHostSchema()
    schema.context[HOSTNAME_VALIDATION_OPTION] = HOSTNAME_VALIDATION_OPTIONS.disabled.name
    with pytest.raises(ValidationError) as e:
        schema.validate_hostnames(test_input)
    assert str(e.value) == 'Invalid hostname "".'
