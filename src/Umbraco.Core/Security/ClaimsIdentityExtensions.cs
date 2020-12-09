// Copyright (c) Umbraco.
// See LICENSE for more details.

using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace Umbraco.Core.Security
{
    /// <summary>
    /// Extension methods for ClaimsIdentity to replace UmbracoBackOfficeIdentity.
    /// </summary>
    public static class ClaimsIdentityExtensions
    {
        private static string _issuer = Constants.Security.BackOfficeAuthenticationType;

        /// <summary>
        /// Gets the required claim types for a back office identity
        /// </summary>
        /// <remarks>
        /// This does not include the role claim type or allowed apps type since that is a collection and in theory could be empty
        /// </remarks>
        public static IEnumerable<string> RequiredBackOfficeIdentityClaimTypes => new[]
        {
            ClaimTypes.NameIdentifier, // id
            ClaimTypes.Name, // username
            ClaimTypes.GivenName,
            Constants.Security.StartContentNodeIdClaimType,
            Constants.Security.StartMediaNodeIdClaimType,
            ClaimTypes.Locality,
            Constants.Security.SecurityStampClaimType
        };

        /// <summary>
        /// Validates that the ClaimsIdentity has all the required claims to be used for backoffice.
        /// </summary>
        /// <param name="identity">Identity to verify</param>
        /// <returns>Returns true if the identity has all required claims.</returns>
        public static bool HasRequiredBackofficeClaims(this ClaimsIdentity identity)
        {
            foreach (var claimType in RequiredBackOfficeIdentityClaimTypes)
            {
                if (identity.HasClaim(x => x.Type == claimType) == false ||
                    identity.HasClaim(x => x.Type == claimType && x.Value.IsNullOrWhiteSpace()))
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Adds required claims for Umbraco backoffice.
        /// </summary>
        /// <param name="claimsIdentity">Identity to add claims to</param>
        /// <param name="userId">User ID to add as claim.</param>
        /// <param name="username">User name to add as claim.</param>
        /// <param name="realName">Real name to add as claim.</param>
        /// <param name="startContentNodes">Allowed start content nodes to add as claims.</param>
        /// <param name="startMediaNodes">Allowed start media nodes to add as claims.</param>
        /// <param name="culture">Culture to add as locality claim.</param>
        /// <param name="securityStamp">Security stamp to add as claim.</param>
        /// <param name="allowedApps">Allowed apps to add as claims.</param>
        /// <param name="roles">Roles to add as claims.</param>
        public static ClaimsIdentity AddRequiredBackofficeClaims(
            this ClaimsIdentity claimsIdentity,
            string userId,
            string username,
            string realName,
            IEnumerable<int> startContentNodes,
            IEnumerable<int> startMediaNodes,
            string culture,
            string securityStamp,
            IEnumerable<string> allowedApps,
            IEnumerable<string> roles)
        {
            // This is the id that 'identity' uses to check for the user id
            if (claimsIdentity.HasClaim(x => x.Type == ClaimTypes.NameIdentifier) == false)
            {
                claimsIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userId, ClaimValueTypes.String, _issuer, _issuer, claimsIdentity));
            }

            if (claimsIdentity.HasClaim(x => x.Type == ClaimTypes.Name) == false)
            {
                claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, username, ClaimValueTypes.String, _issuer, _issuer, claimsIdentity));
            }

            if (claimsIdentity.HasClaim(x => x.Type == ClaimTypes.GivenName) == false)
            {
                claimsIdentity.AddClaim(new Claim(ClaimTypes.GivenName, realName, ClaimValueTypes.String, _issuer, _issuer, claimsIdentity));
            }

            if (claimsIdentity.HasClaim(x => x.Type == Constants.Security.StartContentNodeIdClaimType) == false &&
                startContentNodes != null)
            {
                foreach (var startContentNode in startContentNodes)
                {
                    claimsIdentity.AddClaim(new Claim(Constants.Security.StartContentNodeIdClaimType, startContentNode.ToInvariantString(), ClaimValueTypes.Integer32, _issuer, _issuer, claimsIdentity));
                }
            }

            if (claimsIdentity.HasClaim(x => x.Type == Constants.Security.StartMediaNodeIdClaimType) == false &&
                startMediaNodes != null)
            {
                foreach (var startMediaNode in startMediaNodes)
                {
                    claimsIdentity.AddClaim(new Claim(Constants.Security.StartMediaNodeIdClaimType, startMediaNode.ToInvariantString(), ClaimValueTypes.Integer32, _issuer, _issuer, claimsIdentity));
                }
            }

            if (claimsIdentity.HasClaim(x => x.Type == ClaimTypes.Locality) == false)
            {
                claimsIdentity.AddClaim(new Claim(ClaimTypes.Locality, culture, ClaimValueTypes.String, _issuer, _issuer, claimsIdentity));
            }

            // The security stamp claim is required.
            if (claimsIdentity.HasClaim(x => x.Type == Constants.Security.SecurityStampClaimType) == false)
            {
                claimsIdentity.AddClaim(new Claim(Constants.Security.SecurityStampClaimType, securityStamp, ClaimValueTypes.String, _issuer, _issuer, claimsIdentity));
            }

            // Add each app as a separate claim
            if (claimsIdentity.HasClaim(x => x.Type == Constants.Security.AllowedApplicationsClaimType) == false &&
                allowedApps != null)
            {
                foreach (var application in allowedApps)
                {
                    claimsIdentity.AddClaim(new Claim(Constants.Security.AllowedApplicationsClaimType, application, ClaimValueTypes.String, _issuer, _issuer, claimsIdentity));
                }
            }

            // Claims are added by the ClaimsIdentityFactory because our UserStore supports roles, however this identity might
            // not be made with that factory if it was created with a different ticket so perform the check
            if (claimsIdentity.HasClaim(x => x.Type == ClaimsIdentity.DefaultRoleClaimType) == false && roles != null)
            {
                // Manually add the claims
                foreach (var roleName in roles)
                {
                    claimsIdentity.AddClaim(new Claim(claimsIdentity.RoleClaimType, roleName, ClaimValueTypes.String, _issuer, _issuer, claimsIdentity));
                }
            }

            return claimsIdentity;
        }

        /// <summary>
        /// Gets the type of authenticated identity.
        /// </summary>
        /// <returns>
        /// The type of authenticated identity. This property always returns "UmbracoBackOffice".
        /// </returns>
        public static string GetAuthenticationType(this ClaimsIdentity claimsIdentity) => _issuer;

        /// <summary>
        /// Get all the start content node ids associated with the ClaimsIdentity.
        /// </summary>
        /// <param name="claimsIdentity">this</param>
        /// <returns>Array of content node ids.</returns>
        public static int[] GetStartContentNodes(this ClaimsIdentity claimsIdentity) =>
            claimsIdentity
                .FindAll(x => x.Type == Constants.Security.StartContentNodeIdClaimType)
                .Select(app => int.TryParse(app.Value, out var i) ? i : default)
                .Where(x => x != default).ToArray();

        /// <summary>
        /// Get all the start media node ids associated with the ClaimsIdentity.
        /// </summary>
        /// <param name="claimsIdentity">this</param>
        /// <returns>Array of media node ids.</returns>
        public static int[] GetStartMediaNodes(this ClaimsIdentity claimsIdentity) =>
            claimsIdentity
                .FindAll(x => x.Type == Constants.Security.StartMediaNodeIdClaimType)
                .Select(app => int.TryParse(app.Value, out var i) ? i : default)
                .Where(x => x != default).ToArray();

        /// <summary>
        /// Get all the allowed applications associated with the ClaimsIdentity.
        /// </summary>
        /// <param name="claimsIdentity">this</param>
        /// <returns>Array of allowed applications.</returns>
        public static string[] GetAllowedApplications(this ClaimsIdentity claimsIdentity) =>
            claimsIdentity
                .FindAll(x => x.Type == Constants.Security.AllowedApplicationsClaimType)
                .Select(app => app.Value).ToArray();

        /// <summary>
        /// Get the ID of the ClaimsIdentity.
        /// </summary>
        /// <param name="claimsIdentity">this</param>
        /// <returns>The id of the ClaimsIdentity</returns>
        public static int GetId(this ClaimsIdentity claimsIdentity) =>
            int.Parse(claimsIdentity.FindFirstValue(ClaimTypes.NameIdentifier));

        /// <summary>
        /// Get the given name of the identity.
        /// </summary>
        /// <param name="claimsIdentity">this</param>
        /// <returns>The given name of the identity</returns>
        public static string GetRealName(this ClaimsIdentity claimsIdentity) =>
            claimsIdentity.FindFirstValue(ClaimTypes.GivenName);

        /// <summary>
        /// Get the user name of the identity.
        /// </summary>
        /// <param name="claimsIdentity">this</param>
        /// <returns>The username of the identity</returns>
        public static string GetUsername(this ClaimsIdentity claimsIdentity) =>
            claimsIdentity.FindFirstValue(ClaimTypes.Name);

        /// <summary>
        /// Get the locality of the identity.
        /// </summary>
        /// <param name="claimsIdentity">this</param>
        /// <returns>The locality of the identity</returns>
        public static string GetCulture(this ClaimsIdentity claimsIdentity) =>
            claimsIdentity.FindFirstValue(ClaimTypes.Locality);

        /// <summary>
        /// Get the security stamp associated with the ClaimsIdentity
        /// </summary>
        /// <param name="claimsIdentity">this</param>
        /// <returns>Security stamp associated with the ClaimsIdentity</returns>
        public static string GetSecurityStamp(this ClaimsIdentity claimsIdentity) =>
            claimsIdentity.FindFirstValue(Constants.Security.SecurityStampClaimType);

        /// <summary>
        /// Get the roles associated with the identity.
        /// </summary>
        /// <param name="claimsIdentity">this</param>
        /// <returns>Array of roles</returns>
        public static string[] GetRoles(this ClaimsIdentity claimsIdentity) => claimsIdentity
            .FindAll(x => x.Type == ClaimsIdentity.DefaultRoleClaimType)
            .Select(role => role.Value).ToArray();
    }
}
