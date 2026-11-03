export class HttpError extends Error {
  constructor(
    public readonly statusCode: number,
    message: string,
  ) {
    super(message);
  }
}

/** One message for every auth failure, so responses don't reveal which check failed. */
export const authFailed = () => new HttpError(401, 'authentication failed');
