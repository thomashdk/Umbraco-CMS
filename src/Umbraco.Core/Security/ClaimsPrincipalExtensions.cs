using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using Umbraco.Core;
using Umbraco.Core.Security;

namespace Umbraco.Extensions
{
    public static class ClaimsPrincipalExtensions
    {
        /// <summary>
        /// Gets the required claim types for a back office identity
        /// </summary>
        /// <remarks>
        /// This does not include the role claim type or allowed apps type since that is a collection and in theory could be empty
        /// </remarks>
        public static IEnumerable<string> RequiredBackOfficeIdentityClaimTypes => new[]
        {
            ClaimTypes.NameIdentifier, // id
            ClaimTypes.Name,  // username
            ClaimTypes.GivenName,
            // Constants.Security.StartContentNodeIdClaimType, are these actually required? They aren't set in the tests.
            // Constants.Security.StartMediaNodeIdClaimType,
            ClaimTypes.Locality,
            Constants.Security.SecurityStampClaimType
        };

        /// <summary>
        /// Verifies that a principal objects contains a valid and authenticated ClaimsIdentity for backoffice.
        /// </summary>
        /// <param name="user">Extended principal</param>
        /// <returns>A valid and authenticated ClaimsIdentity</returns>
        public static ClaimsIdentity VerifyBackOfficeIdentity(this IPrincipal user)
        {
            if (!(user.Identity is ClaimsIdentity claimsIdentity))
            {
                // If the identity type is not ClaimsIdentity it's not a BackOfficeIdentity.
                return null;
            }

            if (!claimsIdentity.IsAuthenticated)
            {
                // If the identity isn't authenticated count it as invalid.
                return null;
            }

            foreach (var claimType in RequiredBackOfficeIdentityClaimTypes)
            {
                // If the identity doesn't have the claim or if the value is null it's not a valid BackOfficeIdentity.
                if (claimsIdentity.HasClaim(x => x.Type == claimType) == false
                    || claimsIdentity.HasClaim(x => x.Type == claimType && x.Value.IsNullOrWhiteSpace()))
                {
                    return null;
                }
            }

            return claimsIdentity;
        }

        /// <summary>
        /// Returns the remaining seconds on an auth ticket for the user based on the claim applied to the user durnig authentication
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public static double GetRemainingAuthSeconds(this IPrincipal user) => user.GetRemainingAuthSeconds(DateTimeOffset.UtcNow);

        /// <summary>
        /// Returns the remaining seconds on an auth ticket for the user based on the claim applied to the user durnig authentication
        /// </summary>
        /// <param name="user"></param>
        /// <param name="now"></param>
        /// <returns></returns>
        public static double GetRemainingAuthSeconds(this IPrincipal user, DateTimeOffset now)
        {
            var claimsPrincipal = user as ClaimsPrincipal;
            if (claimsPrincipal == null)
            {
                return 0;
            }

            var ticketExpires = claimsPrincipal.FindFirst(Constants.Security.TicketExpiresClaimType)?.Value;
            if (ticketExpires.IsNullOrWhiteSpace())
            {
                return 0;
            }

            var utcExpired = DateTimeOffset.Parse(ticketExpires, null, DateTimeStyles.RoundtripKind);

            var secondsRemaining = utcExpired.Subtract(now).TotalSeconds;
            return secondsRemaining;
        }
    }
}
