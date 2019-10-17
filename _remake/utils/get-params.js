const pathMatch = require('path-match')({});
import parseUrl from "parseurl";
import RemakeStore from "../lib/remake-store";
import { capture } from "./async-utils";
import { doesPageExist } from "./page-utils";

/*
  Remake has 3 types of routes
  • BaseRoute
  • UsernameRoute
  • ItemRoute

  Combined, these routes can render these patterns:
  • /
  • /pageName
  • /username
  • /username/pageName/
  • /username/pageName/id

  Assumptions:
  • If there's no first param, there are no params
*/

export async function getParams ({req, fromReferrer}) {
  let pathname;

  if (!fromReferrer) {
    pathname = parseUrl(req).pathname;
  } else {
    let url = new URL(req.get('Referrer'));
    pathname = url.pathname;
  }

  let [params] = await capture(getParamsFromPathname(pathname));

  return params;
}

// get params from a generic pathname

async function getParamsFromPathname (pathname) {
  let routeMatcher = pathMatch("/:firstParam?/:secondParam?/:thirdParam?/:fourthParam?");
  let params = routeMatcher(pathname) || [];
  let invalidAppName = false;

  let {firstParam, secondParam, thirdParam, fourthParam} = params;

  let appName, username, pageName, itemId;
  if (!RemakeStore.isMultiTenant()) {
    [username, pageName, itemId] = [firstParam, secondParam, thirdParam];
  } else {
    [appName, username, pageName, itemId] = [firstParam, secondParam, thirdParam, fourthParam];

    if (!appName) {
      return {multiTenantBaseRoute: true};
    } else {
      if (!appName.startsWith("app_")) {
        invalidAppName = true;
        appName = undefined;
      } else {
        appName = appName.replace(/^app_/, "");
      }
    }
  }

  // route: /
  if (!username) {
    pageName = "index";
  }

  if (username && !pageName) {
    let [pageExists] = await capture(doesPageExist({appName, pageName: username}));
    
    if (pageExists) {
      // route: /pageName 
      pageName = username;
      username = undefined;
    } else {
      // route: /username
      pageName = "index";
    }
  }

  return {appName, username, pageName, itemId, invalidAppName};
}