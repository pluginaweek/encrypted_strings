module PluginAWeek #:nodoc:
  module Encrypts #:nodoc:
    def self.included(base) #:nodoc:
      base.extend(MacroMethods)
    end
    
    module MacroMethods
      #
      def encrypts(attr_name, options = {})
        encrypts_with(attr_name, SHAEncryptedString, options)
      end
      alias_method :encrypts_sha, :encrypts
      
      #
      def encrypts_asymmetrically(attr_name, options = {})
        encrypts_with(attr_names, AsymmetricallyEncryptedString, options)
      end
      alias_method :encrypts_asmmetric, :encrypts_asymmetrically
      
      #
      def encrypts_symmetrically(attr_name, options = {})
        encrypts_with(attr_names, SymmetricallyEncryptedString, options)
      end
      alias_method :encrypts_symmetric, :encrypts_symmetrically
      
      private
      def encrypts_with(attr_name, klass, options = {}) #:nodoc:
        options.reverse_merge!(
          :crypted_name => "crypted_#{attr_name}"
        )
        crypted_attr_name = options.delete(:crypted_name)
        raise ArgumentError, 'Attribute name cannot be same as crypted name' if attr_name == crypted_attr_name
        
        # Creator accessor for the virtual attribute
        attr_accessor attr_name
        
        # Define the reader when reading the crypted value from the db
        var_name = "@#{crypted_attr_name}"
        reader_options = options.dup
        reader_options[:encrypt] = false
        define_method(crypted_attr_name) do
          if (data = instance_variable_get(var_name)).nil? && (data = read_attribute(crypted_attr_name)) && !data.blank? && !data.is_a?(klass)
            data = instance_variable_set(var_name, create_encrypted_string(klass, data, reader_options))
          end
          
          data
        end
        
        # Set the value immediately before validation takes place
        before_validation do |model|
          value = model.send(attr_name)
          return if value.blank?
          
          unless value.is_a?(EncryptedString)
            value = model.send(:create_encrypted_string, klass, value, options)
          end
          
          model.send("#{crypted_attr_name}=", value)
        end
        
        # After saving, be sure to reset the virtual attribute value
        after_save do |model|
          model.send("#{attr_name}=", nil)
          model.send("#{attr_name}_confirmation=", nil) if model.respond_to?("#{attr_name}_confirmation=")
        end
        
        include PluginAWeek::Encrypts::InstanceMethods
      end
    end
    
    module InstanceMethods #:nodoc:
      private
      def create_encrypted_string(klass, value, options)
        if klass.respond_to?(:process_options)
          options = options.dup
          klass.process_options(self, options)
        else
          options
        end
        
        klass.new(value, options)
      end
    end
  end
end

class SHAEncryptedString
  def self.process_options(model, options) #:nodoc:
    if (salt_attr_name = options[:salt]) && (salt_attr_name == true || salt_attr_name.is_a?(Symbol))
      salt_attr_name = 'salt' if salt_attr_name == true
      
      if options[:encrypt]
        salt_value = model.send("create_#{salt_attr_name}").to_s
        model.send("#{salt_attr_name}=", salt_value)
      else
        salt_value = model.send(salt_attr_name)
      end
      
      options[:salt] = salt_value
    end
  end
end

ActiveRecord::Base.class_eval do
  include PluginAWeek::Encrypts
end