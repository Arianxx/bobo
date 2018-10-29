##############################################################################
#
# Copyright Zope Corporation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""Create WSGI-based web applications.
"""

# Public names:
__all__ = (
    'Application',
    'early',
    'late',
    'NotFound',
    'order',
    'post',
    'preroute',
    'query',
    'redirect',
    'reroute',
    'resource',
    'resources',
    'scan_class',
    'subroute',
)

# 这个模块中的所有类都会以 type 为元类
# 在 py2 中，使得所有类都为新式类
__metaclass__ = type

import inspect
import logging
import re
import sys
import webob
import six
from six.moves import filter, urllib

log = logging.getLogger(__name__)

bbbbad_errors = KeyboardInterrupt, SystemExit, MemoryError

_default_content_type = 'text/html; charset=UTF-8'

_json_content_type = re.compile('application/json;?').match

# 内省函数参数信息
getargspec = inspect.getargspec if six.PY2 else inspect.getfullargspec


class Application:
    """Create a WSGI application.

    The DEFAULT argument, if given, is a dictionary of options.
    Keyword options override options given in the DEFAULT options.

    Option values are strings, typically read from ConfigParser files.

    The values used by bobo, ``bobo_resources``, ``bobo_configure``
    and ``bobo_errors``, can have comments.  Lines within these
    values are truncated at the first '#' characters.

    The one required option is bobo_resources:

    bobo_resources
       Specifies resources to be used.

       This option can be used to:

       - Specify modules to be scanned for resources.
       - Include specific resources, rather than all resources in given modules.
       - Override the order of resources given in modules.
       - Override routes used for resources given in modules.

       Resources are specified on separate lines.  Resources take one
       of 4 forms:

       module_name
          Use the resources from the given module.

       resource
          Use the named resource.

          The resource is of the form: modulename:expression.  The
          object is obtained by evaluating the expression in the named
          module.

       route -> resource
          The given route, possibly with placeholders, is
          handled by the given resource.

          The resource is of the form: modulename:expression.

          The object named by the resource must meet one of the following
          conditions:

          - It was created using one of the bobo decorators:
            ``resource``, ``post``, ``query``, or ``subroute``.

          - It has ``bobo_reroute`` method that takes the given route
            and returns a new resource. (The bobo decorators provide this.)

          - It is a class, in which case it is treated as a subroute.

          Newlines may be included between the"->" and the resource, allowing
          the specification to be split over multiple lines.

       route +> resource
          The given route, which may not have placeholder, is added as
          a prefix of the given resource's route.

          The resource is of the form: modulename:expression, or just
          modulename.

          Newlines may be included between the"+>" and the resource, allowing
          the specification to be split over multiple lines.

    Bobo also used the following options:

    bobo_configure
       Specify one or more (whitespace-delimited) callables to be
       called with the configuration data passed to the application.

       Each callable is of the form: module_name:global_namen

    bobo_errors
       Specify an object to be used for generating error responses.
       The value must be a module name or an object name of the form:
       ``modulename:expression``.  The object must have the
       callable attributes:

       not_found(request, method)
          Generate a response when a resource can't be found.

          This should return a 404 response.

       method_not_allowed(request, method, methods)
          Generate a response when the resource found doesn't allow the
          request method.

          This should return a 405 response and set the ``Allowed`` response
          header to the list of allowed headers.

       missing_form_variable(request, method, name)
          Generate a response when a form variable is missing.

          The proper response in this situation isn't obvious.

       exception(request, method, ex_info)
          Generate a response for the exception information given by
          exc_info.  This method is optional.  Bobo's default behavior
          is to simply re-raise the exception.

    bobo_handle_exceptions
        Boolean indicating whether bobo should catch application exceptions.

        This defaults to True. It should be set to false if WSGI
        middleware should handle exceptions.

        If provides as a string (through configuration), it should be
        either 'true' or 'false'.

    """

    def __init__(self, DEFAULT=None, **config):
        """
        根据配置执行一系列初始化：
        1. 根据已有 config 调用 bobo_configure 指定的回调函数
        2. 根据 bobo_errors 添加全局错误处理函数
        3. 根据 bobo_resources 解析路由、资源映射
        4. 配置是否抛出异常
        """
        if DEFAULT:
            DEFAULT = dict(DEFAULT)
            DEFAULT.update(config)
            config = DEFAULT

        self.config = config

        bobo_configure = config.get('bobo_configure', '')
        if isinstance(bobo_configure, six.string_types):
            # 如果是字符串，解析为对应的处理函数
            bobo_configure = (
                #
                _get_global(name)
                for name in filter(None, _uncomment(bobo_configure).split())
            )
        for configure in bobo_configure:
            configure(config)

        bobo_errors = config.get('bobo_errors')
        if bobo_errors is not None:
            if isinstance(bobo_errors, six.string_types):
                # 同上
                bobo_errors = _uncomment(bobo_errors)
                if ':' in bobo_errors:
                    bobo_errors = _get_global(bobo_errors)
                else:
                    bobo_errors = _import(bobo_errors)

            # 如果存在，将这些错误处理函数复制到本实例中相应属性
            _maybe_copy(bobo_errors, 'not_found', self)
            _maybe_copy(bobo_errors, 'method_not_allowed', self)
            _maybe_copy(bobo_errors, 'missing_form_variable', self)
            _maybe_copy(bobo_errors, 'exception', self)

        bobo_resources = config.get('bobo_resources', '')
        if isinstance(bobo_resources, six.string_types):
            bobo_resources = _uncomment(bobo_resources, True)
            if bobo_resources:
                # 根据 resource 字符串，解析对应的 route、resource
                self.handlers = _route_config(bobo_resources)
            else:
                raise ValueError("Missing bobo_resources option.")
        else:
            self.handlers = [r.bobo_response for r in bobo_resources]

        handle_exceptions = config.get('bobo_handle_exceptions', True)
        if isinstance(handle_exceptions, six.string_types):
            handle_exceptions = handle_exceptions.lower() == 'true'
        # 默认不抛出异常
        self.reraise_exceptions = not handle_exceptions

    def bobo_response(self, request, path, method):
        """
        轮询注册的 handler 返回第一个有效响应
        并且对相应的异常进行处理
        """
        try:
            allowed = set()
            for handler in self.handlers:
                try:
                    response = handler(request, path, method)
                except MethodNotAllowed as exc:
                    allowed.update(exc.allowed)
                    continue
                if response is not None:
                    # 有响应就直接返回，否则可能路由不匹配，继续遍历
                    return response
            if allowed:
                # 遍历完仍没有返回，并且 allowed 不为空，说明使用了不受支持的
                # 方法
                return self.method_not_allowed(request, method, allowed)
            return self.not_found(request, method)
        except BoboException as exc:
            # 返回了不合法的 response，根据返回值构建合法的 wsgi response 对象
            return self.build_response(request, method, exc)
        except MissingFormVariable as v:
            # 从各种途径获取不到处理函数想要获取的参数
            return self.missing_form_variable(request, method, v.name)
        except NotFound:
            # 显示抛出 not found
            return self.not_found(request, method)
        except bbbbad_errors:
            # 无论如何不应被忽略的致命异常
            raise
        except Exception as exc:
            if (self.reraise_exceptions or
                request.environ.get("x-wsgiorg.throw_errors")
                ):
                # 指定不捕获其余错误，则再次抛出
                raise
            return self.exception(request, method, sys.exc_info())

    def __call__(self, environ, start_response):
        """
        使得本实例为合法的 wsgi app
        Handle a WSGI application request.
        """
        request = webob.Request(environ)
        if request.charset is None:
            # Maybe middleware can be more tricky?
            request.charset = 'utf8'

        return self.bobo_response(request, request.path_info, request.method
                                  )(environ, start_response)

    def build_response(self, request, method, data):
        """
        如果应用没有返回一个有效的 response 响应，如原生的字符串等，就尝试将它转换
        为一个有效的 response 响应再返回

        Build a response object from raw data.

        This method is used by bobo when an application returns data rather
        than a response object.  It can be overridden by subclasses to support
        alternative request implementations. (For example, some implementations
        may have response objects on a request that influence how a response is
        generated.)

        The data object has several attributes:

        status
            Integer HTTP status code

        body
            Raw body data as returned from an application

        content_type
            The desired content type

        headers
            A list of header name/value pairs.
        """

        content_type = data.content_type
        response = webob.Response(status=data.status,
                                  headerlist=data.headers)
        response.content_type = content_type

        if method == 'HEAD':
            # 如果请求方法为 HEAD，说明只想要获取 http head，不需要产生 body，直接返回
            return response

        body = data.body
        # 根据返回值的类型设定不同的 response body
        if isinstance(body, six.text_type):
            response.text = body
        elif isinstance(body, six.binary_type):
            response.body = body
        elif _json_content_type(content_type):
            # 如果请求类型是 json，则序列化 body 为 json
            import json
            response.body = json.dumps(body).encode("utf-8")
        else:
            # 否则返回值不能转化为一个合法的 wsgi resposne 对象
            raise TypeError('bad response', body, content_type)

        return response

    def not_found(self, request, method):
        return _err_response(
            404, method, "Not Found",
            "Could not find: " + urllib.parse.quote(
                request.path_info.encode("utf-8")))

    def missing_form_variable(self, request, method, name):
        return _err_response(
            403, method,
            "Missing parameter", 'Missing form variable %s' % name)

    def method_not_allowed(self, request, method, methods):
        return _err_response(
            405, method,
            "Method Not Allowed", "Invalid request method: %s" % method,
            [('Allow', ', '.join(sorted(methods)))])

    def exception(self, request, method, exc_info):
        log.exception(request.url)
        return _err_response(
            500, method,
            "Internal Server Error", "An error occurred.")


def _err_response(status, method, title, message, headers=()):
    response = webob.Response(status=status, headerlist=headers or [])
    response.content_type = 'text/html; charset=UTF-8'
    if method != 'HEAD':
        response.unicode_body = _html_template % (title, message)
    return response


_html_template = u"""<html>
<head><title>%s</title></head>
<body>%s</body>
</html>
"""


def redirect(url, status=302, body=None,
             content_type="text/html; charset=UTF-8"):
    """Generate a response to redirect to a URL.

    The optional ``status`` argument can be used to supply a status other than
    302.  The optional ``body`` argument can be used to specify a response
    body. If not specified, a default body is generated based on the URL given
    in the ``url`` argument.
    """
    if body is None:
        body = u'See %s' % url

    # if isinstance(url, six.text_type):
    #     url = url.encode('utf-8')

    # 使用 Location 头进行重定向
    response = webob.Response(status=status, headerlist=[('Location', url)])
    response.content_type = content_type
    response.unicode_body = body
    return response


class BoboException(Exception):

    def __init__(self, status, body,
                 content_type='text/html; charset=UTF-8', headers=None):
        self.status = status
        self.body = body
        self.content_type = content_type
        self.headers = headers or []


def _scan_module(module_name):
    # Scan a module for resources, and return a generator of resources
    # in order. The order is defined by:
    # - Order in source
    # - Overridden order
    # - route grouping
    # In particular, wrt the last bullet, resources with the same route
    # are grouped with the order of the first route.
    module = _import(module_name)
    bobo_response = getattr(module, 'bobo_response', None)
    # 如果模块有 bobo_response 这个属性就直接返回
    if bobo_response is not None:
        yield bobo_response
        return

    resources = []
    for resource in six.itervalues(module.__dict__):
        # 否则就检查这个模块的所有属性
        bobo_response = getattr(resource, 'bobo_response', None)
        if bobo_response is None:
            # 跳过没有 bobo_response 值的属性
            continue
        # Check for unbound handler and skip
        if getattr(bobo_response, "__self__", None) is None:
            # 跳过非实例属性
            continue

        # 可以为 resource 指定顺序，或者采用默认递增的顺序值
        order = getattr(resource, 'bobo_order', 0) or _late_base
        resources.append((order, resource, bobo_response))

    resources.sort(key=lambda o: o[0])
    # 可以返回不同对象对应的 bobo_response，并且将这些对象的 route 和 method 统一
    # 收集到 by_route 字典里
    by_route = {}
    for order, resource, bobo_response in resources:
        route = getattr(resource, 'bobo_route', None)
        # 如果为 bobo_response 指定了 bobo_route
        # 就做一些相关处理
        if route is not None:
            # 有 bobo_route，则也需要有 bobo_methods
            methods = getattr(resource, 'bobo_methods', 0)
            if methods != 0:
                # 根据 bobo_route 寻找这个 route 是否已经被保存过
                by_methods = by_route.get(route)
                if not by_methods:
                    # 如果还没有 bobo_route 对应的 method，就新建字典保存
                    by_methods = by_route[route] = {}
                    # 第一次遇到相应 route，构造一个对应这个 route 的 bobo_response 处理函数
                    # 这个函数根据给定 route 和 method，寻找 by_methods 里对应的处理函数
                    yield _make_br_function_by_methods(route, by_methods)
                if methods is None:
                    methods = (methods, )
                for method in methods:
                    # 将方法注册到 by_methods，从而供之前返回的函数查询
                    if method not in by_methods:
                        by_methods[method] = bobo_response
                continue

        # 如果没有指明路径，就直接返回实例的 bobo_response
        yield bobo_response


def _make_br_function_by_methods(route, by_method):
    # Build a bobo_response function for one or more resources for a
    # given route that define both route and methodd (standard
    # resources, iow).

    # 根据 route 获得相应参数的函数
    route_data = _compile_route(route)

    def bobo_response_function_by_method(request, path, method):
        handler = by_method.get(method)
        # 如果没有储存具体方法的处理函数，就寻找默认函数
        if handler is None:
            handler = by_method.get(None)
        if handler is None:
            # 不支持请求方法，且没有默认方法。
            # 那么查看本路由是否就是请求的路由
            data = route_data(request, path)
            if data is not None:
                # 是就抛出不支持的异常
                raise MethodNotAllowed(by_method)
            # 否则返回 None 以交给下一个处理函数
            return None

        # 传递给具体的方法处理
        return handler(request, path, method)

    return bobo_response_function_by_method


def _uncomment(text, split=False):
    """
    去除给定文本里的注释
    """
    result = list(filter(None, (
        line.split('#', 1)[0].strip()
        for line in text.strip().split('\n')
    )))
    if split:
        return result
    return '\n'.join(result)


def _maybe_copy(ob1, name, ob2):
    if hasattr(ob1, name):
        setattr(ob2, name, getattr(ob1, name))


class _MultiResource(list):
    def bobo_response(self, request, path, method):
        for resource in self:
            r = resource(request, path, method)
            if r is not None:
                return r


def resources(resources):
    """
    将指定的 resources 封装为 handle 数组
    Create a resource from multiple resources

    A new resource is returned that works by searching the given resources in
    the order they're given.
    """
    handlers = _MultiResource()
    for resource in resources:
        if isinstance(resource, six.string_types):
            if ':' in resource:
                resource = _get_global(resource)
            else:
                resource = _MultiResource(_scan_module(resource))
        elif getattr(resource, 'bobo_response', None) is None:
            resource = _MultiResource(_scan_module(resource.__name__))

        handlers.append(resource.bobo_response)

    return handlers


def reroute(route, resource):
    """Create a new resource from a re-routable resource.

    The resource can be a string, in which case it should be a global
    name, of the form ``module:expression``.
    """
    if isinstance(resource, six.string_types):
        resource = _get_global(resource)

    try:
        # 如果指定了 resource 已经有自定义的 bobo_reroute，就直接使用
        bobo_reroute = resource.bobo_reroute
    except AttributeError:
        # 否则没有 bobo_reroute 且是对象，交给 subroute 处理
        if isinstance(resource, six.class_types):
            return Subroute(route, resource)
        raise TypeError("Expected a reroutable")
    return bobo_reroute(route)


def preroute(route, resource):
    """Create a new resource by adding a route prefix

    The given route is used as a subroute that is matched before
    matching the given resource's route.

    The resource can be a string, in which case it should be a global
    name, of the form ``module:expression``, or a module name.  If a
    module name is given, and the module doesn't have a
    bobo_response function, then a resource is computed that tries
    each of the resources found in the module in order.
    """
    if isinstance(resource, six.string_types):
        if ':' in resource:
            resource = _get_global(resource)
        else:
            # 与 reroute 不同在于，此处 resource 可以为一个模块名
            resource = _MultiResource(_scan_module(resource))
    elif getattr(resource, 'bobo_response', None) is None:
        resource = _MultiResource(_scan_module(resource.__name__))

    return Subroute(route, lambda request: resource)


_resource_re = re.compile('\s*([\S]+)\s*([-+]>)\s*(\S+)?\s*$').match


def _route_config(lines):
    """
    将设置文件里的字符串解析为具体 bobo_response 构成的列表
    """
    resources = []
    lines.reverse()
    while lines:
        route = lines.pop()
        m = _resource_re(route)
        if m is None:
            sep = resource = None
        else:
            route, sep, resource = m.groups()

        if not resource:
            if not sep:
                # route is the resource.
                if ':' in route:
                    resources.append(_get_global(route).bobo_response)
                else:
                    resources.extend(_scan_module(route))
                continue
            else:
                # line continuation
                # resource 可以在 ->/+> 的下一行
                resource = lines.pop()

        if sep == '->':
            # 将 resource 指定的处理函数重置为另一个 route
            resource = reroute(route, resource)
        else:
            # 指定 route 为 resource route 的前缀
            resource = preroute(route, resource)

        # resources 本质是 bobo_response 构成的列表
        resources.append(resource.bobo_response)

    return resources


def _get_global(attr):
    if ':' in attr:
        mod, attr = attr.split(':', 1)
    elif not mod:
        raise ValueError("No ':' in global name", attr)
    mod = _import(mod)
    return eval(attr, mod.__dict__)


def _import(module_name):
    return __import__(module_name, {}, {}, ['*'])


_order = 0


def order():
    """Return an integer that can be used to order a resource.

    The function returns a larger integer each time it is called.  A
    resource can use this to set it's ``bobo_order`` attribute.
    """
    global _order
    _order += 1
    return _order


_late_base = 1 << 99


def late():
    """Return an order used for resources that should be searched late.

    The function returns a larger integer each time it is called.  The
    value is larger than values returned by the order or early
    functions.
    """
    return order() + _late_base


_early_base = -_late_base


def early():
    """Return an order used for resources that should be searched early.

    The function returns a larger integer each time it is called.  The
    value is smaller than values returned by the order or late
    functions.
    """
    return order() + _early_base


class _cached_property(object):
    def __init__(self, func):
        self.func = func

    def __get__(self, inst, class_):
        # get 描述符
        # 这个类的实例作为属性被访问时返回这个方法的结果
        return self.func(inst)


_ext_re = re.compile('/(\w+)').search


class _Handler:
    # Handlers wrap functions to provide the bobo resource interface.
    #
    # They handle requests by calling the undelying functions.
    #
    # An added complication is that handlers can be stacked, for
    # example to use the same function for multiple routes. In
    # addition, handlers can be called like the original function.

    partial = False

    def __init__(self, route, handler,
                 method=None, params=None, check=None, content_type=None,
                 order_=None):
        if route is None:
            # 如果没有指定路由，就根据处理调用对象的名，和 content_type 自动生成
            # 一个路由
            route = '/'+handler.__name__
            # 根据 content_type 决定是否在自动生成的路由后面添加一个
            # 资源类型名
            ext = _ext_re(content_type)
            if ext:
                route += '.'+ext.group(1)
        self.bobo_route = route
        if isinstance(method, six.string_types):
            method = (method, )
        self.bobo_methods = method
        # 记得吗，_scan_module 中就曾根据这些属性生成了 bobo_response 处理函数

        self.handler = handler
        self.bobo_original = getattr(handler, 'bobo_original', handler)
        bobo_sub_find = getattr(handler, 'bobo_response', None)
        if bobo_sub_find is not None:
            # We're stacked on another handler.
            self.bobo_sub_find = bobo_sub_find

        self.content_type = content_type
        self.params = params
        self.check = check
        if order_ is None:
            order_ = order()
        self.bobo_order = order_

    @_cached_property
    def bobo_handle(self):
        """
        实际处理请求的方法
        """
        func = original = self.bobo_original
        if self.params:
            # func 被包装了从route，request等不同途径自动获得参数的逻辑
            func = _make_caller(func, self.params)
        # func 被包装产生合法 wsgi response 对象的逻辑
        func = _make_bobo_handle(func, original, self.check, self.content_type)
        # 第一次访问属性，会被 _cached_property 转换为描述符执行，返回最终方法
        # 然后在 __dict__ 里替换自己
        # 这样就只需构建一次实际执行的 func
        self.__dict__['bobo_handle'] = func
        return func

    @_cached_property
    def match(self):
        """
        检查路由是否匹配，并获取路由中匹配的 data
        """
        route_data = _compile_route(self.bobo_route, self.partial)
        methods = self.bobo_methods
        # 如果有设置 methods，就检查 methods 是否支持，再返回路由信息
        # 否则直接返回
        if methods is None:
            match = route_data
        else:
            def match(request, path, method):
                data = route_data(request, path)
                if data is not None:
                    if method not in methods:
                        raise MethodNotAllowed(methods)
                    return data

        # 替换自身，缓存构建的 match 函数
        self.__dict__['match'] = match
        return match

    def bobo_response(self, *args):
        request, path, method = args[-3:]
        route_data = self.match(request, path, method)
        if route_data is None:
            # 如果路径路由不匹配，交给 handler 里的 bobo_response 继续处理
            return self.bobo_sub_find(*args)

        # 匹配就直接处理
        # args[:-2] 使得最后一个参数为 request
        # 第一个参数是被描述属性的实例
        return self.bobo_handle(*args[:-2], **route_data)
        # TODO: 可能出现的问题。如果实例化时传入 partial 为 true，则生成的 self.match
        # 因该返回的是一个元组。然而这里直接假设返回了字典

    def bobo_sub_find(self, *args):
        pass

    def __call__(self, *args, **kw):
        # 使得 resource 可以手动提供参数直接调用
        return self.bobo_original(*args, **kw)

    def __get__(self, inst, class_):
        # 可作为描述符使用
        # _UnboundHandler 和 _BoundHandler 实际上也是描述符
        # 能根据被描述属性实例与否，作出不同的响应
        # 只有被描述的属性实例化，这个属性才会具有 bobo_response 方法，并且传入
        # 那个实例调用本实例的 bobo_response
        if inst is None:
            return _UnboundHandler(self, class_)
        return _BoundHandler(self, inst, class_)

    @property
    def func_code(self):
        return six.get_function_code(self.bobo_original)

    @property
    def func_defaults(self):
        return six.get_function_defaults(self.bobo_original)

    @property
    def __name__(self):
        return self.bobo_original.__name__

    def bobo_reroute(self, route):
        # 直接替换 route
        return self.__class__(route, self.bobo_original, self.bobo_methods,
                              self.params, self.check, self.content_type)


class _UnboundHandler:

    im_self = None

    def __init__(self, handler, class_):
        self.im_func = handler
        self.im_class = class_

    def __get__(self, inst, class_):
        if inst is None:
            return self
        # 如果装饰的属性是被实例的对象，就返回以这个实例构造的 _BoundHandler 实例
        return _BoundHandler(self.im_func, inst, self.im_class)

    def __repr__(self):
        return "<unbound resource %s.%s>" % (
            self.im_class.__name__,
            self.im_func.__name__,
        )

    def _check_args(self, args):
        # 第一个参数需要是被修饰的属性的类的实例
        if not args or not isinstance(args[0], self.im_class):
            raise TypeError("Need %s initial argument"
                            % self.im_class.__name__)

    def __call__(self, *args, **kw):
        self._check_args(args)
        return self.im_func(*args, **kw)


class _BoundHandler:

    def __init__(self, handler, inst, class_):
        if not isinstance(inst, class_):
            raise TypeError("Can't bind", inst, class_)
        self.im_func = handler
        self.im_self = inst
        self.im_class = class_

    def __repr__(self):
        return "<bound resource %s.%s of %r>" % (
            self.im_class.__name__,
            self.im_func.__name__,
            self.im_self,
        )

    def bobo_response(self, *args):
        return self.im_func.bobo_response(self.im_self, *args)

    def __call__(self, *args, **kw):
        return self.im_func(self.im_self, *args, **kw)


def _handler(route, func=None, **kw):
    if func is None:
        # 使本函数能够当成装饰器使用
        if route is None or isinstance(route, six.string_types):
            return lambda f: _handler(route, f, **kw)
        func = route
        route = None
    elif route is not None:
        assert isinstance(route, six.string_types)
        if route and not route.startswith('/'):
            raise ValueError("Non-empty routes must start with '/'.", route)

    return _Handler(route, func, **kw)


def resource(route=None, method=('GET', 'POST', 'HEAD'),
             content_type=_default_content_type, check=None, order=None):
    """Create a resource

    This function is used as a decorator to define a resource. It can be applied
    to any kind of callable, not just a function.

    Arguments:

    route
        The route to match against a request URL to determine
        if the decorated callable should be used to satisfy a
        request.

        if omitted, a route will be computed using the decorated
        callable's name with the content_type subtype used as an extension.

    method
        The HTTP request method or methods that can be used. This can be either
        a string giving a single method name, or a sequence of strings.

    content_type
        The content_type for the response.

        The content type is ignored if the callable returns a response object.

    check
        A check function.

        If provided, the check function (or callable) will be called
        before the decorated callable.  The check function is passed
        an instance, a request, and the decorated callable.  If the
        resource is a method, then first argument is the instance the
        method was called on, otherwise it is None.  If the check
        function returns a response, the response will be used instead
        of calling the decorated callable.

    order
        The order controls how resources are searched when matching
        URLs.  Normally, resources are searched in order of
        evaluation.  Passing the result of calling ``bobo.early`` or
        ``bobo.late`` can cause resources to be searched early or late.

    The function may be used as a decorator directly without calling
    it. For example::

       @bobo.resource
       def example(request):
           ...

    is equivalent to::

       @bobo.resource()
       def example(request):
           ...

    The callable must take a request object as the first argument.  If the
    route has placeholders, then the callable must accept named parameters
    corresponding to the placeholders.  The named parameters must have defaults
    for any optional placeholders.

    Unlike the post and query decorators, this decorator doesn't introspect the
    callable it's applied to.
    """
    return _handler(route, method=method, check=check,
                    content_type=content_type, order_=order)


def post(route=None, content_type=_default_content_type, check=None,
         order=None):
    """Create a resource that passes POST data as arguments

    This function is used as a function decorator to define a resource.

    Arguments:

    route
        The route to match against a request URL to determine
        if the decorated callable should be used to satisfy a
        request.

        if omitted, a route will be computed using the decorated
        callable's name with the content_type subtype used as an extension.

    content_type
        The content_type for the response.

        The content type is ignored if the callable returns a response object.

    check
        A check function.

        If provided, the check function (or callable) will be called
        before the decorated function.  The check function is passed
        an instance, a request, and the decorated function.  If the
        resource is a method, then first argument is the instance the
        method was called on, otherwise it is None.  If the check
        function returns a response, the response will be used instead
        of calling the decorated function.

    order
        The order controls how resources are searched when matching
        URLs.  Normally, resources are searched in order of
        evaluation.  Passing the result of calling ``bobo.early`` or
        ``bobo.late`` can cause resources to be searched early or late.

    The function may be used as a decorator directly without calling
    it. For example::

       @bobo.post
       def example():
           ...

    is equivalent to::

       @bobo.post()
       def example():
           ...

    The callable the decorator is applied to is analyzed to determine it's
    signature.  When the callable is called, the request, route data and
    request form data are used to satisfy any named arguments in the callable's
    signature.  For example, in the case of::

       @bobo.post('/:a')
       def example(bobo_request, a, b, c=None):
           ...

    when handling a request for: ``http://localhost/x``, with a post
    body of ``b=1``, the request is passed to the ``bobo_request``
    argument. the route data value ``'x'`` is passed to the argument
    ``a``, and the form data ``1`` is passed for ``b``.

    Standard function metadata attributes ``func_code`` and ``func_defaults``
    are used to determine the signature and required arguments. The method
    attribute, ``im_func`` is used to determine if the callable is a method, in
    which case the first argument found in the signature is ignored.
    """
    return _handler(route, method="POST", params='POST', check=check,
                    content_type=content_type, order_=order)


def query(route=None, method=('GET', 'POST', 'HEAD'),
          content_type=_default_content_type, check=None, order=None):
    """Create a resource that passes form data as arguments

    Create a decorator that, when applied to a callable, creates a
    resource.

    Arguments:

    route
        The route to match against a request URL to determine if the decorated
        callable should be used to satisfy a request.

        if omitted, a route will be computed using the decorated
        callable's name with the content_type subtype used as an extension.

    method
        The HTTP request method or methods that can be used. This can
        be either a string giving a single method name, or a sequence
        of strings.

        The method argument defaults to the tuple ``('GET', 'HEAD', 'POST')``.

    content_type
        The content_type for the response.

        The content type is ignored if the callable returns a response object.

    check
        A check function.

        If provided, the check function (or callable) will be called
        before the decorated function.  The check function is passed
        an instance, a request, and the decorated function.  If the
        resource is a method, then first argument is the instance the
        method was called on, otherwise it is None.  If the check
        function returns a response, the response will be used instead
        of calling the decorated function.

    order
        The order controls how resources are searched when matching
        URLs.  Normally, resources are searched in order of
        evaluation.  Passing the result of calling ``bobo.early`` or
        ``bobo.late`` can cause resources to be searched early or late.

    The function may be used as a decorator directly without calling
    it. For example::

       @bobo.query
       def example():
           ...

    is equivalent to::

       @bobo.query()
       def example():
           ...

    The callable the decorator is applied to is analyzed to determine it's
    signature.  When the callable is called, the request, route data and
    request form data are used to satisfy any named arguments in the callable's
    signature.  For example, in the case of::

       @bobo.query('/:a')
       def example(bobo_request, a, b, c=None):
           ...

    when handling a request for: ``http://localhost/x?b=1``,
    the request is passed to the ``bobo_request`` argument. the route
    data value ``'x'`` is passed to the argument ``a``, and the form
    data ``1`` is passed for ``b``.

    Standard function metadata attributes ``func_code`` and
    ``func_defaults`` are used to determine the signature and required
    arguments. The method attribute, ``im_func`` is used to determine
    if the callable is a method, in which case the first argument found
    in the signature is ignored.
    """
    return _handler(route, method=method, params='params', check=check,
                    content_type=content_type, order_=order)


def get(route, content_type=_default_content_type, check=None, order=None):
    """Create a resource that handles GET requests.

    Arguments:

    route
        The route to match against a request URL to determine if the decorated
        callable should be used to satisfy a request.

        if omitted, a route will be computed using the decorated
        callable's name with the content_type subtype used as an extension.

    content_type
        The content_type for the response.

        The content type is ignored if the callable returns a response object.

    check
        A check function.

        If provided, the check function (or callable) will be called
        before the decorated function.  The check function is passed
        an instance, a request, and the decorated function.  If the
        resource is a method, then first argument is the instance the
        method was called on, otherwise it is None.  If the check
        function returns a response, the response will be used instead
        of calling the decorated function.

    order
        The order controls how resources are searched when matching
        URLs.  Normally, resources are searched in order of
        evaluation.  Passing the result of calling ``bobo.early`` or
        ``bobo.late`` can cause resources to be searched early or late.
    """
    return _handler(route, method="GET", check=check, params="params",
                    content_type=content_type, order_=order)


def head(route, content_type=_default_content_type, check=None, order=None):
    """Create a resource that handles HEAD requests.

    Arguments:

    route
        The route to match against a request URL to determine if the decorated
        callable should be used to satisfy a request.

        if omitted, a route will be computed using the decorated
        callable's name with the content_type subtype used as an extension.

    content_type
        The content_type for the response.

        The content type is ignored if the callable returns a response object.

    check
        A check function.

        If provided, the check function (or callable) will be called
        before the decorated function.  The check function is passed
        an instance, a request, and the decorated function.  If the
        resource is a method, then first argument is the instance the
        method was called on, otherwise it is None.  If the check
        function returns a response, the response will be used instead
        of calling the decorated function.

    order
        The order controls how resources are searched when matching
        URLs.  Normally, resources are searched in order of
        evaluation.  Passing the result of calling ``bobo.early`` or
        ``bobo.late`` can cause resources to be searched early or late.
    """
    return _handler(route, method="HEAD", params="params", check=check,
                    content_type=content_type, order_=order)


def put(route, content_type=_default_content_type, check=None, order=None):
    """Create a resource that handles PUT requests.

    Arguments:

    route
        The route to match against a request URL to determine if the decorated
        callable should be used to satisfy a request.

        if omitted, a route will be computed using the decorated
        callable's name with the content_type subtype used as an extension.

    content_type
        The content_type for the response.

        The content type is ignored if the callable returns a response object.

    check
        A check function.

        If provided, the check function (or callable) will be called
        before the decorated function.  The check function is passed
        an instance, a request, and the decorated function.  If the
        resource is a method, then first argument is the instance the
        method was called on, otherwise it is None.  If the check
        function returns a response, the response will be used instead
        of calling the decorated function.

    order
        The order controls how resources are searched when matching
        URLs.  Normally, resources are searched in order of
        evaluation.  Passing the result of calling ``bobo.early`` or
        ``bobo.late`` can cause resources to be searched early or late.
    """
    return _handler(route, method="PUT", check=check, params="POST",
                    content_type=content_type, order_=order)


def delete(route, content_type=_default_content_type, check=None, order=None):
    """Create a resource that handles DELETE requests.

    Arguments:

    route
        The route to match against a request URL to determine if the decorated
        callable should be used to satisfy a request.

        if omitted, a route will be computed using the decorated
        callable's name with the content_type subtype used as an extension.

    content_type
        The content_type for the response.

        The content type is ignored if the callable returns a response object.

    check
        A check function.

        If provided, the check function (or callable) will be called
        before the decorated function.  The check function is passed
        an instance, a request, and the decorated function.  If the
        resource is a method, then first argument is the instance the
        method was called on, otherwise it is None.  If the check
        function returns a response, the response will be used instead
        of calling the decorated function.

    order
        The order controls how resources are searched when matching
        URLs.  Normally, resources are searched in order of
        evaluation.  Passing the result of calling ``bobo.early`` or
        ``bobo.late`` can cause resources to be searched early or late.
    """
    return _handler(route, method="DELETE", check=check,
                    content_type=content_type, order_=order)


def options(route, content_type=_default_content_type, check=None, order=None):
    """Create a resource that handles OPTIONS requests.

    Arguments:

    route
        The route to match against a request URL to determine if the decorated
        callable should be used to satisfy a request.

        if omitted, a route will be computed using the decorated
        callable's name with the content_type subtype used as an extension.

    content_type
        The content_type for the response.

        The content type is ignored if the callable returns a response object.

    check
        A check function.

        If provided, the check function (or callable) will be called
        before the decorated function.  The check function is passed
        an instance, a request, and the decorated function.  If the
        resource is a method, then first argument is the instance the
        method was called on, otherwise it is None.  If the check
        function returns a response, the response will be used instead
        of calling the decorated function.

    order
        The order controls how resources are searched when matching
        URLs.  Normally, resources are searched in order of
        evaluation.  Passing the result of calling ``bobo.early`` or
        ``bobo.late`` can cause resources to be searched early or late.
    """
    return _handler(route, method="OPTIONS", params="params", check=check,
                    content_type=content_type, order_=order)


route_re = re.compile(r'(/:[a-zA-Z]\w*\??)(\.[^/]+)?')


def _compile_route(route, partial=False):
    """
    生成根据给定路径解析对应路由，返回其中包含的关键字参数的函数
    """
    assert route.startswith('/') or not route
    # split 扫描整个字符串并将与模式匹配与否的部分相互分开
    # 并且匹配完整的模式一遍就会加一个 None 以分隔
    pat = route_re.split(route)
    # 反转以方便 pop
    pat.reverse()
    rpat = []
    prefix = pat.pop()
    # 静态前缀，如果没有会是一个空字符串
    if prefix:
        rpat.append(re.escape(prefix))
    while pat:
        name = pat.pop()[2:]
        optional = name.endswith('?')
        if optional:
            name = name[:-1]
        # 构造一个具名匹配组，匹配组 / 以外的字符
        name = '/(?P<%s>[^/]*)' % name
        ext = pat.pop()
        if ext:
            name += re.escape(ext)
        if optional:
            # 如果这个路由可选择，则包围以可选择的匹配组
            name = '(%s)?' % name
        rpat.append(name)
        s = pat.pop()
        if s:
            # 静态后缀
            rpat.append(re.escape(s))

    if partial:
        # 如果提供了 partial，表明只匹配一部分路径
        match = re.compile(''.join(rpat)).match

        def partial_route_data(request, path, method=None):
            m = match(path)
            if m is None:
                return m
            path = path[len(m.group(0)):]
            # 那么返回关键字参数和剩余路径
            return (dict(item for item in six.iteritems(m.groupdict())
                         if item[1] is not None),
                    path,
                    )

        return partial_route_data
    else:
        # 没有partial，匹配到结尾
        match = re.compile(''.join(rpat)+'$').match

        def route_data(request, path, method=None):
            m = match(path)
            if m is None:
                return m
            # 直接返回对应参数
            return dict(item for item in six.iteritems(m.groupdict())
                        if item[1] is not None)

        return route_data


def _make_bobo_handle(func, original, check, content_type):
    """
    将 func 获得的结果转换为一个合法的 wsgi response 
    """

    def handle(*args, **route):
        if check is not None:
            # 如果装饰 handler 函数时提供了 check，则会
            # 尝试调用 check 函数，如果 check 返回了值
            # 就将这个值作为 response，否则调用被装饰函数
            if len(args) == 1:
                # 被装饰的 handler 是否是一个类方法
                result = check(None, args[0], original)
            else:
                result = check(args[0], args[1], original)
            if result is not None:
                return result
        result = func(*args, **route)

        # 如果 result 是一个可调用对象
        # 就视 result 为一个可返回 wsgi response 的合法对象
        if hasattr(result, '__call__'):
            return result

        # 否则抛出异常转换 result
        raise BoboException(200, result, content_type)

    return handle


_no_jget = {}.get


def _make_caller(obj, paramsattr):
    """
    封装 obj callable，从 route，request body 等途径
    提供它想要的参数
    """
    spec = getargspec(obj)
    nargs = nrequired = len(spec.args)
    if spec.defaults:
        nrequired -= len(spec.defaults)
    no_jget = _no_jget

    # XXX maybe handle f(..., **kw)?

    def bobo_apply(*pargs, **route):
        # 根据 Application 中对 handler 传入 request, method, path
        # 再在 _Handler 中脱去了 method 和 path 可知
        # 最后一个参数是 reqeust
        request = pargs[-1]
        pargs = pargs[:-1]  # () or (self, )
        # paramsattr 指定请求方法，即，从哪里获取数据
        # 如果 paramsattr 为 post，则会获取请求 post 中的数据
        params = getattr(request, paramsattr)
        rget = route.get
        pget = params.getall
        jget = 0
        # kw 是根据路由和函数指定的参数名，要实际传给调用的函数的参数
        kw = {}
        for index in range(len(pargs), nargs):
            name = spec.args[index]
            if name == 'bobo_request':
                # 如果处理函数里有名为 bobo_request，就将 request 对象设为
                # 参数的值
                kw[name] = request
                continue

            # 参数是否出现在捕获的路由里面
            v = rget(name)
            if v is None:
                v = pget(name)
                if v:
                    if len(v) == 1:
                        v = v[0]
                else:
                    if jget == 0:
                        # 如果指定的参数既不在路由里面
                        # 也不在 pget（？） 里面
                        # 并且请求的内容类型为 json
                        # 就尝试在上传的 json 数据里面获取
                        if request.content_type == 'application/json':
                            jget = request.json.get
                        else:
                            jget = no_jget
                    v = jget(name, request)
                    if v is request:
                        if index < nrequired:
                            # 从路由或request里面都获取不到指定的参数
                            # 就抛出异常
                            raise MissingFormVariable(name)
                        continue

            kw[name] = v

        return obj(*pargs, **kw)

    return bobo_apply


class Subroute(_Handler):

    partial = True

    def __init__(self, route, handler):
        _Handler.__init__(self, route, handler)

    def bobo_response(self, *args):
        request, path, method = args[-3:]
        route_data = self.match(request, path)
        if route_data is None:
            return self.bobo_sub_find(*args)

        route_data, path = route_data
        resource = self.bobo_original(*args[:-2], **route_data)
        # 子路由装饰的 callable 处理完前缀之后，需要返回一个处理接下来路由的 resource
        if resource is not None:
            return resource.bobo_response(request, path, method)

    def bobo_reroute(self, route):
        return self.__class__(route, self.bobo_original)


def _subroute(route, ob, scan):
    if scan:
        scan_class(ob)
        return _subroute_class(route, ob)

    if isinstance(ob, six.class_types):
        return _subroute_class(route, ob)

    # 如果被装饰的是一个函数，这个函数需要返回一个 resource，见 Subroute
    return Subroute(route, ob)


def subroute(route=None, scan=False, order=None):
    """Create a resource that matches a URL in multiple steps

    If called with a route or without any arguments, subroute returns
    an object that should then be called with a resource factory.  The
    resource factory will be called with a request and route data and
    should return a resource object.  For example::

       @subroute('/:employee_id', scan=True)
       class EmployeeView:
           def __init__(self, request, employee_id):
               ...

    If no route is supplied, the ``__name__`` attribute of the callable
    is used.

    The resource factory may return None to indicate that a resource can't be
    found on the subroute.

    The scan argument, if given, should be given as a keyword
    parameter. It defaults to False.  If True, then the callable
    should be a class and a ``bobo_response`` instance method will be
    added to the class that calls resources found by scanning the
    class and its base classes.  Passing a True ``scan``
    argument is equivalent to calling ``scan_class``::

       @subroute('/:employee_id')
       @scan_class
       class EmployeeView:
           def __init__(self, request, employee_id):

    ``subroute`` can be passed a callable directly, as in::

       @subroute
       class Employees:
           def __init__(self, request):
               ...
           def bobo_response(self, request, path, method):
               ...

    Which is equivalent to calling ``subroute`` without the callable
    and then passing the callable to the route::

       @subroute()
       class Employees:
           def __init__(self, request):
               ...
           def bobo_response(self, request, path, method):
               ...

    Note that in the example above, the scan argument isn't passed and
    defaults to False, so the class has to provide it's own
    ``bobo_response`` method (or otherwise arrange that instances have one).

    The optional ``order`` parameter controls how resources are
    searched when matching URLs.  Normally, resources are searched in
    order of evaluation.  Passing the result of calling ``bobo.early``
    or ``bobo.late`` can cause resources to be searched early or late.
    It is usually a good idea to use ``bobo.late`` for subroutes that
    match any URL.
    """

    if route is None:
        return lambda ob: _subroute('/'+ob.__name__, ob, scan)
    if isinstance(route, six.string_types):
        return lambda ob: _subroute(route, ob, scan)
    return _subroute('/'+route.__name__, route, scan)


class _subroute_class_method(object):
    def __init__(self, class_, class_func, inst_func):
        self.class_ = class_
        self.class_func = class_func
        self.inst_func = inst_func

    def __get__(self, inst, class_):
        if inst is None:
            return self.class_func.__get__(class_, type(class_))
        inst_func = self.inst_func
        if inst_func is None:
            try:
                return super(self.class_, inst).bobo_response
            except TypeError:
                raise AttributeError(
                    "%s instance has no attribute 'bobo_response'"
                    % inst.__class__.__name__)
        return inst_func.__get__(inst, class_)


def _subroute_class(route, ob):
    matchers = ob.__dict__.get('bobo_subroute_matchers', None)
    if matchers is None:
        matchers = ob.bobo_subroute_matchers = []
    matchers.append(_compile_route(route, True))

    br_orig = getattr(ob, 'bobo_response', None)
    if br_orig is not None:

        # TODO: 这里 __self__ 可能会为 class ? 元类 ?
        if inspect.isclass(getattr(br_orig, "__self__", None)):
            # we found another class method.
            if len(matchers) > 1:
                # stacked matchers, so we're done
                return ob
            if (('bobo_response' in ob.__dict__)
                    or not hasattr(ob, '__mro__')):
                del ob.bobo_subroute_matchers
                raise TypeError("bobo_response class method already defined")
            # ok, it's inherited, we'll use super if necessary
            br_orig = None

    def bobo_response(self, request, path, method):
        for matcher in matchers:
            route_data = matcher(route, path)
            if route_data:
                route_data, path = route_data
                resource = ob(request, **route_data)
                if resource is not None:
                    # 因为 resource 是已经实例化的 ob，所以这里的 bobo_response
                    # 调用会转发到 ob 父类上的 bobo_response，或者 br_orig 上
                    return resource.bobo_response(request, path, method)

    ob.bobo_response = _subroute_class_method(ob, bobo_response, br_orig)
    return ob


def scan_class(class_):
    """Create an instance bobo_response method for a class

    Scan a class (including its base classes) for resources and generate
    a bobo_response method of the class that calls them.
    """

    resources = {}
    # 得到所有父类上的 resource
    for c in reversed(inspect.getmro(class_)):
        for name, resource in six.iteritems(c.__dict__):
            br = getattr(resource, 'bobo_response', None)
            if br is None:
                continue
            order = getattr(resource, 'bobo_order', 0) or _late_base
            resources[name] = order, resource

    by_route = {}
    handlers = []
    # 将这些 resource 按照 route、method 或 name 集合到一起
    for (order, (name, resource)) in sorted(
        (order, (name, resource))
        for (name, (order, resource)) in six.iteritems(resources)
    ):
        route = getattr(resource, 'bobo_route', None)
        if route is not None:
            methods = getattr(resource, 'bobo_methods', 0)
            if methods != 0:
                by_methods = by_route.get(route)
                if not by_methods:
                    by_methods = by_route[route] = {}
                    handlers.append(
                        _make_br_method_by_methods(route, by_methods))
                if methods is None:
                    methods = (methods, )
                for method in methods:
                    if method not in by_methods:
                        by_methods[method] = name
                continue

        handlers.append(_make_br_method_for_name(name))

    def instance_bobo_response(self, request, path, method):
        allowed = set()
        # 遍历父类上收集的 handlers
        for handler in handlers:
            try:
                found = handler(self, request, path, method)
            except MethodNotAllowed as exc:
                allowed.update(exc.allowed)
                continue
            if found is not None:
                return found
        if allowed:
            raise MethodNotAllowed(allowed)

    old = class_.__dict__.get('bobo_response')
    if isinstance(old, _subroute_class_method):
        old.inst_func = instance_bobo_response
    else:
        class_.bobo_response = instance_bobo_response

    return class_


def _make_br_method_for_name(name):
    def custom_bobo_response_method(self, request, path, method):
        # Handle a resource that just has bobo_response, but no metadata
        return getattr(self, name).bobo_response(request, path, method)
    return custom_bobo_response_method


def _make_br_method_by_methods(route, methods):
    # Make a combined bobo_response for one or more standard instance
    # resource that have a common route and are distinguished by the
    # methods they support.
    route_data = _compile_route(route)

    def bobo_response_method_by_methods(self, request, path, method):
        name = methods.get(method)
        if name is None:
            name = methods.get(None)
        if name is None:
            data = route_data(request, path)
            if data is not None:
                raise MethodNotAllowed(methods)
            return None

        return getattr(self, name).bobo_response(request, path, method)

    return bobo_response_method_by_methods


class MissingFormVariable(Exception):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return self.name


class MethodNotAllowed(Exception):
    def __init__(self, allowed):
        self.allowed = sorted(allowed)

    def __str__(self):
        return "Allowed: %s" % repr(self.allowed)[1:-1]


class NotFound(Exception):
    """A resource cannot be found.

    This exception can be conveniently raised by application
    code. Bobo will catch it and generate a not-found response object.
    """
