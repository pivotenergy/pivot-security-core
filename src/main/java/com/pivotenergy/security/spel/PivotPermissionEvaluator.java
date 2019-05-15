/*
 * ________________________________________________________________________
 * METRO.IO CONFIDENTIAL
 * ________________________________________________________________________
 *
 * Copyright (c) 2017.
 * Metro Labs Incorporated
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains
 * the property of Metro Labs Incorporated and its suppliers,
 * if any. The intellectual and technical concepts contained
 * herein are proprietary to Metro Labs Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Metro Labs Incorporated.
 */

package com.pivotenergy.security.spel;

import com.pivotenergy.security.model.UserSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.Serializable;

import static com.pivotenergy.security.model.UserSession.Role.Action.ADMIN;
import static com.pivotenergy.security.model.UserSession.Role.Target.GLOBAL;

@SuppressWarnings("WeakerAccess")
@Component
public class PivotPermissionEvaluator implements PermissionEvaluator {
    private Logger LOG = LoggerFactory.getLogger(PivotPermissionEvaluator.class);

    @Override
    public boolean hasPermission(Authentication auth, Object domainObject, Object permission) {
        if (isNull(auth, domainObject) || !isPermissionInValid(permission)) {
            return false;
        }

        String target, action = String.valueOf(permission);
        if (domainObject instanceof String) {
            target = String.valueOf(domainObject);
        }
        else {
            target = domainObject.getClass().getSimpleName();
        }

        return hasPrivilege(auth, UserSession.Role.Target.valueOf(target), UserSession.Role.Action.valueOf(action));
    }

    @Override
    public boolean hasPermission(Authentication auth, Serializable targetId, String target, Object action) {
        if (isNull(auth, target) || isPermissionInValid(action) || target.isEmpty()) {
            return false;
        }
        String _action = String.valueOf(action);
        return hasPrivilege(auth, UserSession.Role.Target.valueOf(target), UserSession.Role.Action.valueOf(_action));
    }

    public boolean hasPrivilege(Authentication auth, UserSession.Role.Target _target, UserSession.Role.Action _action) {
        UserSession user = (UserSession) auth.getDetails();

        for (UserSession.Role role : user.getRoles()) {
            UserSession.Role.Scope scope = role.getScope();
            UserSession.Role.Action action = role.getAction();
            UserSession.Role.Target target = role.getTarget();
            if ((action.equals(ADMIN) || action.equals(_action)) && (target.equals(GLOBAL) || target.equals(_target)))
            {
                LOG.debug("user {} has {} privilege on {} with {} permission",
                        user.getId(), scope, _target, _action);
                return true;
            }
        }

        LOG.debug("{} privilege not found for: {}", _action, _target);
        return false;
    }

    private boolean isPermissionInValid(Object permission) {
        return !(permission instanceof String) || ((String) permission).isEmpty();
    }

    private boolean isNull(Authentication auth, Object target) {
        return auth == null || target == null;
    }
}