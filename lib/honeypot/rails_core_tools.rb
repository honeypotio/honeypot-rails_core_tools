# frozen_string_literal: true

require 'active_record'
require 'base64'
require 'digest'

module Honeypot
  module Graphql
    extend self

    def resolve_type(_abstract_type, obj, _ctx)
      "Types::#{obj.class.name}".constantize
    end

    def id_from_object(object, *_args)
      return 'NULL' if object.id.nil?

      type = object.class.name
      type_and_id = "#{type}.#{object.id}"
      signed_id = "#{type_and_id}.#{digest(type_and_id)}"

      Base64.urlsafe_encode64(signed_id).gsub('=', '')
    end

    def object_from_id(graphql_id, *_args)
      return if graphql_id == 'NULL'

      graphql_id = Base64.urlsafe_decode64(graphql_id)
      type, id, provided_digest = graphql_id.split('.')
      type_and_id = "#{type}.#{id}"

      return if type.nil? || id.nil? || provided_digest.nil?

      raise 'Invalid digest' if provided_digest != digest(type_and_id)

      gid = "gid://#{GlobalID.app}/#{type}/#{id}"
      GlobalID::Locator.locate(gid)
    rescue ArgumentError # base64 cannot be parsed
      nil
    end

    # sign the ids to prevent enumeration attacks
    def digest(id)
      Digest::MD5.hexdigest("#{id}_#{AppConfig.secret_key_base}")[0..5]
    end
  end
end

module ActiveRecord
  class Base
    def graphql_id
      ::Honeypot::Graphql.id_from_object(self)
    end
  end
end
