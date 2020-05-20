#include "olm/olm.h"
#include "self_omemo.h"
#include "sodium.h"
#include "self_olm.h"

static VALUE initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE identity;
    GroupSession *this;

    Data_Get_Struct(self, GroupSession, this);

    (void)rb_scan_args(argc, argv, "1", &identity);

    if(identity != Qnil){
        if(rb_obj_is_kind_of(identity, rb_cString) != Qtrue){
            rb_raise(rb_eTypeError, "identity must be kind of String");
        }
    }

    omemo_set_identity(this, RSTRING_PTR(identity));

    return self;
}

static VALUE add_participant(VALUE self, VALUE identity, VALUE session)
{
    GroupSession *this;
    OlmSession *s;

    Data_Get_Struct(self, GroupSession, this);
    Data_Get_Struct(session, OlmSession, s);

    if(rb_obj_is_kind_of(identity, rb_eval_string("String")) != Qtrue){
        rb_raise(rb_eTypeError, "identity must be kind of String");
    }

    if(
       rb_obj_is_instance_of(session, rb_eval_string("SelfOlm::Session")) != Qtrue &&
       rb_obj_is_instance_of(session, rb_eval_string("SelfOlm::InboundSession")) != Qtrue &&
       rb_obj_is_instance_of(session, rb_eval_string("SelfOlm::OutboundSession")) != Qtrue
     ){
        rb_raise(rb_eTypeError, "session must be an instance of SelfOlm::Session, SelfOlm::InboundSession or SelfOlm::OutboundSession");
    }

    omemo_add_group_participant(this, RSTRING_PTR(identity), s);

    return identity;
}

static void _free(void *ptr)
{
    //omemo_destroy_group_session(ptr);
}

static VALUE _alloc(VALUE klass)
{
    GroupSession *this;
    VALUE self;

    self = Data_Wrap_Struct(klass, 0, _free, omemo_create_group_session());

    Data_Get_Struct(self, GroupSession, this);

    return self;
}

void group_session_init()
{
    VALUE cRubyOLM = rb_define_module("SelfOlm");
    VALUE cGroupSession = rb_define_class_under(cRubyOLM, "GroupSession", rb_cObject);

    rb_define_alloc_func(cGroupSession, _alloc);

    rb_define_method(cGroupSession, "initialize", initialize, -1);
    rb_define_method(cGroupSession, "add_participant", add_participant, 2);
}
